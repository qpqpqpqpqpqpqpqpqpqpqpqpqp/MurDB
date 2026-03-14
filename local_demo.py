from __future__ import annotations
import json
import os
import shutil
import traceback
from pathlib import Path
from murdb_core import analyze_with_llm, build_sqlite_summary, decide_target_prefix
BASE = Path('workspace')
INCOMING = BASE / 'incoming'
MAIN_BACKUPS = BASE / 'main-backups'
QUARANTINE = BASE / 'quarantine'
REPORTS = BASE / 'reports'
LLM_SERVICE_URL = os.environ.get('LLM_SERVICE_URL', 'http://127.0.0.1:8000/analyze')

def ensure_dirs() -> None:
    for directory in [INCOMING, MAIN_BACKUPS, QUARANTINE, REPORTS]:
        directory.mkdir(parents=True, exist_ok=True)

def process_once() -> None:
    ensure_dirs()
    for db_file in sorted(INCOMING.glob('*.db')):
        try:
            summary = build_sqlite_summary(str(db_file))
            llm_result = analyze_with_llm(summary, LLM_SERVICE_URL)
            route = decide_target_prefix(llm_result)
            target_dir = MAIN_BACKUPS if route == 'main-backups' else QUARANTINE
            shutil.copy2(db_file, target_dir / db_file.name)
            report = {'source_key': db_file.name, 'risk_level': llm_result.get('risk_level', 'UNKNOWN'), 'decision': llm_result.get('decision', 'error'), 'route': route, 'explanation': llm_result.get('explanation', ''), 'recommendations': llm_result.get('recommendations', []), 'summary': summary, 'target_path': str(target_dir / db_file.name), 'mode': 'local_demo'}
            report_name = f'{db_file.stem}.report.json'
            (REPORTS / report_name).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
            print(f'обработан {db_file.name}: {route}')
        except Exception as exc:
            error_report = {'source_key': db_file.name, 'risk_level': 'UNKNOWN', 'decision': 'error', 'route': 'error', 'error': str(exc), 'traceback': traceback.format_exc(), 'mode': 'local_demo'}
            report_name = f'{db_file.stem}.error.json'
            (REPORTS / report_name).write_text(json.dumps(error_report, ensure_ascii=False, indent=2), encoding='utf-8')
            print(f'обработан {db_file.name}: ошибка')
        finally:
            if db_file.exists():
                db_file.unlink()
if __name__ == '__main__':
    process_once()
