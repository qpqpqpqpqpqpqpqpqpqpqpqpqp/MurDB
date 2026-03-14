from __future__ import annotations
import json
import math
import re
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any
SUSPICIOUS_NAME_TOKENS = ('password', 'passwd', 'secret', 'token', 'jwt', 'api_key', 'apikey', 'session', 'private_key', 'email', 'phone', 'passport', 'address', 'auth', 'credential')
SECRET_VALUE_KEYWORDS = ('password', 'passwd', 'secret', 'token', 'api key', 'apikey', 'session', 'private key', 'reset token', 'bearer', 'auth', 'credential')
EMAIL_RE = re.compile('^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$', re.IGNORECASE)
JWT_RE = re.compile('^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$')
PHONE_RE = re.compile('^\\+?[0-9][0-9\\-() ]{7,}[0-9]$')
HEX_RE = re.compile('^[0-9a-fA-F]+$')
BASE64ISH_RE = re.compile('^[A-Za-z0-9+/=_-]{20,}$')
PRIVATE_KEY_MARKERS = ('-----BEGIN PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----')

def _truncate(value: Any, limit: int=80) -> str:
    text = repr(value)
    return text[:limit] + ('...' if len(text) > limit else '')

def _looks_suspicious_name(name: str) -> bool:
    lowered = name.lower()
    return any((token in lowered for token in SUSPICIOUS_NAME_TOKENS))

def _safe_table_name(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'

def _validate_sqlite_file(db_path: str) -> None:
    db_file = Path(db_path)
    if not db_file.exists() or not db_file.is_file():
        raise ValueError(f'не найден sqlite-файл: {db_path}')
    with db_file.open('rb') as file_obj:
        header = file_obj.read(16)
    if header != b'SQLite format 3\x00':
        raise ValueError('входной файл не является корректной sqlite-базой данных')
    try:
        con = sqlite3.connect(f'file:{db_file}?mode=ro', uri=True)
        try:
            result = con.execute('PRAGMA quick_check').fetchone()
        finally:
            con.close()
    except sqlite3.DatabaseError as exc:
        raise ValueError(f'входной файл не прошёл проверку sqlite: {exc}') from exc
    if not result or str(result[0]).lower() != 'ok':
        raise ValueError('входной файл не прошёл проверку целостности sqlite')

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum((count / length * math.log2(count / length) for count in counts.values()))
    return round(entropy, 3)

def _contains_secret_keywords(text: str) -> bool:
    lowered = text.lower()
    return any((keyword in lowered for keyword in SECRET_VALUE_KEYWORDS))

def _value_indicators(raw_value: Any) -> dict[str, bool]:
    blank = {'email_like': False, 'phone_like': False, 'jwt_like': False, 'private_key_like': False, 'hash_like': False, 'secret_like': False, 'keyword_secret_like': False}
    if raw_value is None:
        return blank
    text = str(raw_value).strip()
    if not text:
        return blank
    lowered = text.lower()
    email_like = bool(EMAIL_RE.match(text))
    phone_like = bool(PHONE_RE.match(text))
    jwt_like = bool(JWT_RE.match(text))
    private_key_like = any((marker in text for marker in PRIVATE_KEY_MARKERS))
    hash_like = len(text) in {32, 40, 64, 128} and bool(HEX_RE.match(text))
    keyword_secret_like = _contains_secret_keywords(text)
    entropy = _shannon_entropy(text)
    secret_like = jwt_like or private_key_like or keyword_secret_like or (len(text) >= 24 and bool(BASE64ISH_RE.match(text)) and (entropy >= 3.5)) or (len(text) >= 16 and (not email_like) and (not phone_like) and (entropy >= 4.0) and any((ch.isdigit() for ch in text)) and any((ch.isalpha() for ch in text))) or ('sk_' in lowered or ('api' in lowered and len(text) >= 20))
    return {'email_like': email_like, 'phone_like': phone_like, 'jwt_like': jwt_like, 'private_key_like': private_key_like, 'hash_like': hash_like, 'secret_like': secret_like, 'keyword_secret_like': keyword_secret_like}

def _init_column_aggregate(col_name: str, col_type: str) -> dict[str, Any]:
    return {'name': col_name, 'type': col_type or 'UNKNOWN', 'suspicious_name': _looks_suspicious_name(col_name), 'non_null_count': 0, 'min_len': None, 'max_len': 0, 'sum_len': 0, 'digit_chars': 0, 'total_chars': 0, 'unique_values': set(), 'unique_overflow': False, 'email_like_count': 0, 'phone_like_count': 0, 'jwt_like_count': 0, 'private_key_like_count': 0, 'hash_like_count': 0, 'secret_like_count': 0, 'keyword_secret_like_count': 0, 'preview_values': [], 'top_value_counter': Counter()}

def _finalize_column_aggregate(agg: dict[str, Any], row_count: int) -> dict[str, Any]:
    non_null = agg['non_null_count']
    avg_len = round(agg['sum_len'] / non_null, 2) if non_null else 0
    digit_ratio = round(agg['digit_chars'] / agg['total_chars'], 3) if agg['total_chars'] else 0.0
    if agg['unique_overflow']:
        unique_ratio = None
    else:
        unique_ratio = round(len(agg['unique_values']) / non_null, 3) if non_null else 0.0
    content_flags = []
    if agg['secret_like_count']:
        content_flags.append('secret_like_values')
    if agg['keyword_secret_like_count']:
        content_flags.append('keyword_secret_indicators')
    if agg['jwt_like_count']:
        content_flags.append('jwt_like_values')
    if agg['private_key_like_count']:
        content_flags.append('private_key_markers')
    if agg['hash_like_count']:
        content_flags.append('hash_like_values')
    if agg['email_like_count']:
        content_flags.append('email_like_values')
    if agg['phone_like_count']:
        content_flags.append('phone_like_values')
    if agg['suspicious_name']:
        content_flags.append('suspicious_field_name')
    frequent_values = [{'value': _truncate(value, 60), 'count': count} for value, count in agg['top_value_counter'].most_common(3)]
    return {'name': agg['name'], 'type': agg['type'], 'suspicious_name': agg['suspicious_name'], 'non_null_count': non_null, 'null_count': max(row_count - non_null, 0), 'min_len': agg['min_len'] if agg['min_len'] is not None else 0, 'max_len': agg['max_len'], 'avg_len': avg_len, 'digit_ratio': digit_ratio, 'unique_ratio': unique_ratio, 'email_like_count': agg['email_like_count'], 'phone_like_count': agg['phone_like_count'], 'jwt_like_count': agg['jwt_like_count'], 'private_key_like_count': agg['private_key_like_count'], 'hash_like_count': agg['hash_like_count'], 'secret_like_count': agg['secret_like_count'], 'keyword_secret_like_count': agg['keyword_secret_like_count'], 'preview_values': agg['preview_values'], 'frequent_values': frequent_values, 'content_flags': content_flags}

def build_sqlite_summary(db_path: str, preview_rows_per_table: int=3) -> dict[str, Any]:
    _validate_sqlite_file(db_path)
    db_file = Path(db_path)
    summary: dict[str, Any] = {'database_name': db_file.name, 'database_size_bytes': db_file.stat().st_size, 'summary_version': '3.1', 'scan_mode': 'full_database_scan', 'table_count': 0, 'tables': [], 'suspicious_fields': [], 'global_observations': {}}
    con = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    tables = cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    total_rows = 0
    total_columns = 0
    suspicious_count = 0
    tables_with_secret_like_data = 0
    tables_with_pii_like_data = 0
    for row in tables:
        table_name = row[0]
        safe_table = _safe_table_name(table_name)
        columns_info = cur.execute(f'PRAGMA table_info({safe_table})').fetchall()
        columns = [{'name': col[1], 'type': col[2] or 'UNKNOWN'} for col in columns_info]
        total_columns += len(columns)
        aggregates = {col['name']: _init_column_aggregate(col['name'], col['type']) for col in columns}
        table_row_count = 0
        preview_rows: list[dict[str, str]] = []
        row_cursor = con.execute(f'SELECT * FROM {safe_table}')
        for db_row in row_cursor:
            table_row_count += 1
            if len(preview_rows) < preview_rows_per_table:
                preview_rows.append({key: _truncate(db_row[key]) for key in db_row.keys()})
            for col in columns:
                col_name = col['name']
                value = db_row[col_name]
                agg = aggregates[col_name]
                if value is None:
                    continue
                text = str(value)
                length = len(text)
                agg['non_null_count'] += 1
                agg['sum_len'] += length
                agg['max_len'] = max(agg['max_len'], length)
                agg['min_len'] = length if agg['min_len'] is None else min(agg['min_len'], length)
                agg['digit_chars'] += sum((char.isdigit() for char in text))
                agg['total_chars'] += length
                if len(agg['preview_values']) < 3:
                    agg['preview_values'].append(_truncate(value, 60))
                if len(agg['unique_values']) < 5000:
                    agg['unique_values'].add(text)
                else:
                    agg['unique_overflow'] = True
                if len(text) <= 80:
                    agg['top_value_counter'][text] += 1
                indicators = _value_indicators(value)
                for key_name, flag in indicators.items():
                    if flag:
                        agg[f'{key_name}_count'] += 1
        finalized_profiles = []
        table_has_secret = False
        table_has_pii = False
        suspicious_columns = []
        for col in columns:
            profile = _finalize_column_aggregate(aggregates[col['name']], table_row_count)
            finalized_profiles.append(profile)
            if profile['content_flags']:
                suspicious_columns.append(col['name'])
                suspicious_count += 1
                summary['suspicious_fields'].append({'table': table_name, 'column': col['name'], 'type': col['type'], 'reasons': profile['content_flags']})
            if any((flag in profile['content_flags'] for flag in {'secret_like_values', 'keyword_secret_indicators', 'jwt_like_values', 'private_key_markers', 'hash_like_values', 'suspicious_field_name'})):
                table_has_secret = True
            if any((flag in profile['content_flags'] for flag in {'email_like_values', 'phone_like_values'})):
                table_has_pii = True
        if table_has_secret:
            tables_with_secret_like_data += 1
        if table_has_pii:
            tables_with_pii_like_data += 1
        summary['tables'].append({'name': table_name, 'row_count': table_row_count, 'columns': columns, 'suspicious_columns': suspicious_columns, 'sample_preview': preview_rows, 'column_profiles': finalized_profiles})
        total_rows += table_row_count
    con.close()
    summary['table_count'] = len(summary['tables'])
    summary['global_observations'] = {'total_rows': total_rows, 'total_columns': total_columns, 'suspicious_field_count': suspicious_count, 'contains_suspicious_fields': bool(suspicious_count), 'tables_with_secret_like_data': tables_with_secret_like_data, 'tables_with_pii_like_data': tables_with_pii_like_data, 'analysis_scope': 'all_tables_all_columns_all_rows'}
    return summary
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('db_path')
    parser.add_argument('--preview-rows', type=int, default=3)
    args = parser.parse_args()
    print(json.dumps(build_sqlite_summary(args.db_path, args.preview_rows), ensure_ascii=False, indent=2))
