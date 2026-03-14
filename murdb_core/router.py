from __future__ import annotations
VALID_RISK_LEVELS = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
APPROVE_DECISIONS = {'approve', 'approved', 'allow'}
QUARANTINE_DECISIONS = {'quarantine', 'deny', 'blocked', 'block', 'reject'}

def decide_target_prefix(llm_result: dict) -> str:
    risk_level = str(llm_result.get('risk_level', '')).strip().upper()
    decision = str(llm_result.get('decision', 'quarantine')).strip().lower()
    if risk_level not in VALID_RISK_LEVELS:
        return 'quarantine'
    recommendations = llm_result.get('recommendations')
    if recommendations is not None and (not isinstance(recommendations, list)):
        return 'quarantine'
    if risk_level in {'HIGH', 'CRITICAL'}:
        return 'quarantine'
    if decision in APPROVE_DECISIONS and risk_level in {'LOW', 'MEDIUM'}:
        return 'main-backups'
    if decision in QUARANTINE_DECISIONS:
        return 'quarantine'
    return 'quarantine'
