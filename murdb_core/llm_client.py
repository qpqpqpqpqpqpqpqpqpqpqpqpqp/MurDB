from __future__ import annotations
import json
from typing import Any
from urllib import request, error

class LLMServiceError(RuntimeError):
    pass

def analyze_with_llm(summary: dict[str, Any], llm_service_url: str, timeout: int=600) -> dict[str, Any]:
    payload = json.dumps({'summary': summary}).encode('utf-8')
    req = request.Request(llm_service_url, data=payload, headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode('utf-8')
    except error.URLError as exc:
        raise LLMServiceError(f'не удалось выполнить запрос к ии-сервису: {exc}') from exc
    try:
        data = json.loads(raw)
    except Exception as exc:
        raise LLMServiceError(f'ии-сервис вернул некорректный json: {raw[:300]}') from exc
    required = {'risk_level', 'decision', 'explanation'}
    missing = required - set(data.keys())
    if missing:
        raise LLMServiceError(f'в ответе ии отсутствуют поля: {sorted(missing)}')
    return data
