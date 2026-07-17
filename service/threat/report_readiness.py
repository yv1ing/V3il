from sqlmodel import select

from model.threat.analysis import AnalysisRecord, AttackerProfile, IntentAssessment, RiskAssessment
from model.threat.chains import AttackChain
from schema.threat.analysis import AnalysisKind, AttackerProfileStatus, IntentAssessmentStatus
from schema.threat.chains import AttackChainStatus


async def final_report_analysis_error(session, incident_id: int) -> str:
    intent = await _current_payload(session, incident_id, AnalysisKind.INTENT, IntentAssessment)
    if intent is None or intent.status != IntentAssessmentStatus.SUPPORTED:
        return "incident requires a current supported intent assessment"
    chain = await _current_payload(session, incident_id, AnalysisKind.ATTACK_CHAIN, AttackChain)
    if chain is None or chain.status not in {AttackChainStatus.PARTIAL, AttackChainStatus.COMPLETE}:
        return "incident requires a current partial or complete attack chain"
    if chain.status == AttackChainStatus.PARTIAL and not chain.gaps:
        return "partial attack chain must document evidence gaps"
    profile = await _current_payload(
        session,
        incident_id,
        AnalysisKind.ATTACKER_PROFILE,
        AttackerProfile,
    )
    if profile is None or profile.status != AttackerProfileStatus.ACCEPTED:
        return "incident requires a current accepted attacker profile"
    risk = await _current_payload(session, incident_id, AnalysisKind.RISK, RiskAssessment)
    if risk is None:
        return "incident requires a current risk assessment"
    return ""


async def _current_payload(session, incident_id: int, kind: AnalysisKind, model):
    return (await session.exec(
        select(model)
        .join(AnalysisRecord, AnalysisRecord.id == model.analysis_id)
        .where(
            AnalysisRecord.incident_id == incident_id,
            AnalysisRecord.kind == kind,
            AnalysisRecord.is_current.is_(True),
        )
    )).one_or_none()
