from __future__ import annotations

import json
import os
import re
from typing import Any

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title='murdb локальный ии')
OLLAMA_URL = os.environ.get('OLLAMA_URL', 'http://127.0.0.1:11434/api/generate')
OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'llama3.1:8b')
PROMPT_TEMPLATE = """
ты модуль принятия решений по безопасности для загрузок sqlite-файлов.
на вход подаётся структурированное summary sqlite-базы данных.
реши, должен ли файл быть направлен в approved или quarantine.

правила:
- если summary явно указывает на пароли, токены, секреты, api-ключи, сессионные данные, приватные ключи или персональные данные пользователей в потенциально чувствительном контексте, выбирай quarantine.
- если есть сомнения, выбирай quarantine.
- верни только строгий json с ключами: risk_level, decision, explanation, recommendations.
- risk_level должен быть одним из: low, medium, high, critical.
- decision должен быть либо approved, либо quarantine.
- explanation и recommendations пиши на русском и с маленькой буквы.
- recommendations должен быть json-массивом коротких строк.

структурированное summary:
{summary_json}
""".strip()


class AnalyzeRequest(BaseModel):
    summary: dict[str, Any]


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if not match:
        raise ValueError('в ответе ии не найден json-объект')
    return json.loads(match.group(0))


def _normalize_response(data: dict[str, Any]) -> dict[str, Any]:
    risk_level = str(data.get('risk_level', 'CRITICAL')).strip().upper()
    if risk_level not in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
        risk_level = 'CRITICAL'

    decision = str(data.get('decision', 'quarantine')).strip().lower()
    if decision not in {'approved', 'quarantine'}:
        decision = 'quarantine'

    explanation = str(data.get('explanation', 'ии не вернул объяснение')).strip().lower()

    recommendations = data.get('recommendations')
    if not isinstance(recommendations, list):
        recommendations = ['выполни ручную проверку перед дальнейшей обработкой файла']
    else:
        recommendations = [str(item).strip().lower() for item in recommendations if str(item).strip()]
        if not recommendations:
            recommendations = ['выполни ручную проверку перед дальнейшей обработкой файла']

    return {
        'risk_level': risk_level,
        'decision': decision,
        'explanation': explanation,
        'recommendations': recommendations,
    }


def _ollama_decision(summary: dict[str, Any]) -> dict[str, Any]:
    prompt = PROMPT_TEMPLATE.format(summary_json=json.dumps(summary, ensure_ascii=False, indent=2))
    response = requests.post(
        OLLAMA_URL,
        json={'model': OLLAMA_MODEL, 'prompt': prompt, 'stream': False},
        timeout=600,
    )
    response.raise_for_status()
    payload = response.json()
    raw_text = payload.get('response', '')
    data = _extract_json(raw_text)
    return _normalize_response(data)


@app.get('/health')
def health():
    return {
        'status': 'ok',
        'mode': 'ollama',
        'ollama_model': OLLAMA_MODEL,
        'message': 'сервис работает',
    }


@app.post('/analyze')
def analyze(request: AnalyzeRequest):
    try:
        return _ollama_decision(request.summary)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'ии не удалось анализировать: {str(e).lower()}')
