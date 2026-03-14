from __future__ import annotations
import json
import os
import tempfile
import traceback
from pathlib import Path
from typing import Any
import boto3
from murdb_core import analyze_with_llm, build_sqlite_summary, decide_target_prefix
S3_ENDPOINT_URL = os.environ.get('S3_ENDPOINT_URL', 'https://storage.yandexcloud.net')
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_DEFAULT_REGION = os.environ.get('AWS_DEFAULT_REGION', 'ru-central1')
MAIN_BACKUPS_BUCKET = os.environ.get('MAIN_BACKUPS_BUCKET') or os.environ.get('APPROVED_BUCKET')
QUARANTINE_BUCKET = os.environ['QUARANTINE_BUCKET']
REPORTS_BUCKET = os.environ['REPORTS_BUCKET']
LLM_SERVICE_URL = os.environ['LLM_SERVICE_URL']
DELETE_SOURCE_AFTER_ROUTE = os.environ.get('DELETE_SOURCE_AFTER_ROUTE', '1') == '1'
SAMPLE_ROWS_PER_TABLE = int(os.environ.get('SAMPLE_ROWS_PER_TABLE', '3'))
if not MAIN_BACKUPS_BUCKET:
    raise RuntimeError('требуется переменная окружения main_backups_bucket')
session = boto3.session.Session(aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=AWS_DEFAULT_REGION)
s3 = session.client('s3', endpoint_url=S3_ENDPOINT_URL)

def _save_report(report: dict[str, Any], report_key: str) -> None:
    s3.put_object(Bucket=REPORTS_BUCKET, Key=report_key, Body=json.dumps(report, ensure_ascii=False, indent=2).encode('utf-8'), ContentType='application/json')

def _extract_records(event: dict[str, Any]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for msg in event.get('messages', []):
        details = msg.get('details', {})
        bucket = details.get('bucket_id')
        key = details.get('object_id')
        if bucket and key:
            records.append({'bucket': bucket, 'key': key})
    return records

def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    results = []
    for rec in _extract_records(event):
        bucket = rec['bucket']
        key = rec['key']
        local_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                local_path = tmp.name
            s3.download_file(bucket, key, local_path)
            summary = build_sqlite_summary(local_path, SAMPLE_ROWS_PER_TABLE)
            llm_result = analyze_with_llm(summary, LLM_SERVICE_URL)
            route = decide_target_prefix(llm_result)
            target_bucket = MAIN_BACKUPS_BUCKET if route == 'main-backups' else QUARANTINE_BUCKET
            copy_source = {'Bucket': bucket, 'Key': key}
            s3.copy_object(Bucket=target_bucket, Key=key, CopySource=copy_source)
            if DELETE_SOURCE_AFTER_ROUTE:
                s3.delete_object(Bucket=bucket, Key=key)
            report = {'source_bucket': bucket, 'source_key': key, 'risk_level': llm_result.get('risk_level', 'UNKNOWN'), 'decision': llm_result.get('decision', 'error'), 'route': route, 'explanation': llm_result.get('explanation', ''), 'recommendations': llm_result.get('recommendations', []), 'summary': summary, 'target_bucket': target_bucket, 'cloud': 'yandex_cloud'}
            report_key = f'reports/{Path(key).name}.report.json'
            _save_report(report, report_key)
            results.append({'key': key, 'decision': report['decision'], 'route': route, 'report_key': report_key})
        except Exception as exc:
            tb = traceback.format_exc()
            report_key = f'reports/{Path(key).name}.error.json'
            _save_report({'source_bucket': bucket, 'source_key': key, 'risk_level': 'UNKNOWN', 'decision': 'error', 'route': 'error', 'error': str(exc), 'traceback': tb, 'cloud': 'yandex_cloud'}, report_key)
            results.append({'key': key, 'decision': 'error', 'route': 'error', 'error': str(exc), 'report_key': report_key})
        finally:
            if local_path and os.path.exists(local_path):
                os.remove(local_path)
    return {'statusCode': 200, 'body': json.dumps(results, ensure_ascii=False)}
