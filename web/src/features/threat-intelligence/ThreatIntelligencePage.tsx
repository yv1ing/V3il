import { Button, TabPane, Tabs } from "@douyinfe/semi-ui";
import { ArrowRight, FileSearch, Fingerprint, Gauge, ListTree, Radar, ShieldCheck, UserRoundSearch } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { showApiError } from "../../shared/api/feedback";
import { collectAllPages } from "../../shared/api/pagination";
import {
  ATTACKER_PROFILE_STATUS,
  INTELLIGENCE_REPORT_STATUS,
  INTENT_ASSESSMENT_STATUS,
  PAGINATION_MAXIMUM_PAGE_SIZE,
  THREAT_INDICATOR_DISPOSITION,
  THREAT_SEVERITY,
} from "../../shared/api/generated/constants";
import { queryThreatIncidents } from "../../shared/api/threatIncidents";
import {
  queryAttackChains,
  queryAttackerProfiles,
  queryIntelligenceReports,
  queryIntentAssessments,
  queryRiskAssessments,
  queryThreatIndicators,
} from "../../shared/api/threatIntelligence";
import type {
  AttackChain,
  AttackerProfile,
  IntelligenceReport,
  IntentAssessment,
  RiskAssessment,
  ThreatIncident,
  ThreatIndicator,
} from "../../shared/api/types";
import { AsyncContent } from "../../shared/components/AsyncContent";
import { MetricStrip } from "../../shared/components/ResourcePageShell";
import { TabLabel } from "../../shared/components/TabLabel";
import { useAdminResourceHeader } from "../../shared/hooks/useAdminResourceHeader";
import { formatDateTime } from "../../shared/lib/date";
import { formatEnumLabel } from "../../shared/lib/labels";
import { EmptyOperationalState, OperationalSection, OperationalTag } from "../operations/OperationalUi";

type IntelligenceItem<T> = T & { incidentTitle: string };

type IntelligenceData = {
  incidents: ThreatIncident[];
  reports: IntelligenceItem<IntelligenceReport>[];
  indicators: IntelligenceItem<ThreatIndicator>[];
  assessments: IntelligenceItem<IntentAssessment>[];
  chains: IntelligenceItem<AttackChain>[];
  profiles: IntelligenceItem<AttackerProfile>[];
  risks: IntelligenceItem<RiskAssessment>[];
};

const EMPTY_DATA: IntelligenceData = { incidents: [], reports: [], indicators: [], assessments: [], chains: [], profiles: [], risks: [] };

export function ThreatIntelligencePage() {
  const navigate = useNavigate();
  const [data, setData] = useState<IntelligenceData>(EMPTY_DATA);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const incidents = await collectAllPages<ThreatIncident>((page) => queryThreatIncidents({ page, size: PAGINATION_MAXIMUM_PAGE_SIZE, keyword: "" }));
      const intelligence = await Promise.all(incidents.map(async (incident) => {
        const [reports, indicators, assessments, chains, profiles, risks] = await Promise.all([
          collectAllPages<IntelligenceReport>((page) => queryIntelligenceReports(incident.id, { page, size: PAGINATION_MAXIMUM_PAGE_SIZE })),
          collectAllPages<ThreatIndicator>((page) => queryThreatIndicators(incident.id, { page, size: PAGINATION_MAXIMUM_PAGE_SIZE, keyword: "" })),
          collectAllPages<IntentAssessment>((page) => queryIntentAssessments(incident.id, { page, size: PAGINATION_MAXIMUM_PAGE_SIZE })),
          collectAllPages<AttackChain>((page) => queryAttackChains(incident.id, { page, size: PAGINATION_MAXIMUM_PAGE_SIZE })),
          collectAllPages<AttackerProfile>((page) => queryAttackerProfiles(incident.id, { page, size: PAGINATION_MAXIMUM_PAGE_SIZE })),
          collectAllPages<RiskAssessment>((page) => queryRiskAssessments(incident.id, { page, size: PAGINATION_MAXIMUM_PAGE_SIZE })),
        ]);
        const addIncident = <T extends object>(items: T[]): IntelligenceItem<T>[] => (
          items.map((item) => ({ ...item, incidentTitle: incident.title }))
        );
        return {
          reports: addIncident(reports),
          indicators: addIncident(indicators),
          assessments: addIncident(assessments),
          chains: addIncident(chains),
          profiles: addIncident(profiles),
          risks: addIncident(risks),
        };
      }));
      setData({
        incidents,
        reports: intelligence.flatMap((item) => item.reports),
        indicators: intelligence.flatMap((item) => item.indicators),
        assessments: intelligence.flatMap((item) => item.assessments),
        chains: intelligence.flatMap((item) => item.chains),
        profiles: intelligence.flatMap((item) => item.profiles),
        risks: intelligence.flatMap((item) => item.risks),
      });
    } catch (error) {
      showApiError(error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useAdminResourceHeader({ refreshLabel: "Refresh threat intelligence", loading, onRefresh: load });

  const metrics = useMemo(() => [
    { label: "Final Reports", value: data.reports.filter((report) => report.status === INTELLIGENCE_REPORT_STATUS.FINAL).length },
    { label: "Malicious IOCs", value: data.indicators.filter((indicator) => indicator.disposition === THREAT_INDICATOR_DISPOSITION.MALICIOUS).length },
    { label: "Supported Intent", value: data.assessments.filter((assessment) => assessment.status === INTENT_ASSESSMENT_STATUS.SUPPORTED).length },
    { label: "Accepted Profiles", value: data.profiles.filter((profile) => profile.status === ATTACKER_PROFILE_STATUS.ACCEPTED).length },
    { label: "High/Critical Risk", value: data.risks.filter((risk) => risk.severity === THREAT_SEVERITY.HIGH || risk.severity === THREAT_SEVERITY.CRITICAL).length },
  ], [data]);

  return (
    <section className="intelligence-page">
      <MetricStrip metrics={metrics} />
      <AsyncContent loading={loading} empty={data.incidents.length === 0} emptyContent={<EmptyOperationalState icon={<FileSearch size={28} />} label="No incident intelligence available" />}>
        <Tabs type="line" className="workspace-tabs">
          <TabPane itemKey="reports" tab={<TabLabel icon={<FileSearch size={15} />} text={`Reports (${data.reports.length})`} />}>
            <OperationalSection title="Intelligence Reports" count={data.reports.length}>
              {data.reports.length === 0 ? <EmptyOperationalState icon={<FileSearch size={24} />} label="No reports generated" /> : (
                <div className="report-list report-list-wide">
                  {data.reports.map((report) => (
                    <article key={report.id}>
                      <header><div><strong>{report.title}</strong><small>{report.incidentTitle} · {formatDateTime(report.created_at)}</small></div><OperationalTag value={report.status} /></header>
                      <p>{report.executive_summary}</p>
                      <div className="report-risk"><span>Conclusion</span><p>{report.conclusion}</p></div>
                      <footer>
                        <span>{report.analysis_snapshot.length} analysis snapshots</span>
                        <span>{report.evidence_manifest.evidence_ids?.length ?? 0} evidence records</span>
                        {report.knowledge_document_name ? <span><ShieldCheck size={13} /> Knowledge published</span> : null}
                        <Button theme="borderless" icon={<ArrowRight size={14} />} onClick={() => navigate(`/incidents/${report.incident_id}`)}>Incident</Button>
                      </footer>
                    </article>
                  ))}
                </div>
              )}
            </OperationalSection>
          </TabPane>
          <TabPane itemKey="indicators" tab={<TabLabel icon={<Fingerprint size={15} />} text={`Indicators (${data.indicators.length})`} />}>
            <OperationalSection title="Threat Indicators" count={data.indicators.length}>
              {data.indicators.length === 0 ? <EmptyOperationalState icon={<Fingerprint size={24} />} label="No indicators extracted" /> : (
                <div className="intelligence-table" role="table" aria-label="Threat indicators">
                  <div className="intelligence-table-row intelligence-table-head" role="row"><span>Type</span><span>Value</span><span>Disposition</span><span>Confidence</span><span>Incident</span><span>Observed</span></div>
                  {data.indicators.map((indicator) => (
                    <button className="intelligence-table-row" type="button" role="row" key={indicator.id} onClick={() => navigate(`/incidents/${indicator.incident_id}`)}>
                      <span><OperationalTag value={indicator.type} /></span><code>{indicator.value}</code><span><OperationalTag value={indicator.disposition} /></span><span><OperationalTag value={indicator.confidence} /></span><strong>{indicator.incidentTitle}</strong><small>{formatDateTime(indicator.last_observed_at)}</small>
                    </button>
                  ))}
                </div>
              )}
            </OperationalSection>
          </TabPane>
          <TabPane itemKey="analysis" tab={<TabLabel icon={<ListTree size={15} />} text="Intent & Chains" />}>
            <div className="workspace-split">
              <OperationalSection title="Intent Assessments" count={data.assessments.length}>
                {data.assessments.length === 0 ? <EmptyOperationalState icon={<Radar size={24} />} label="No supported intent" /> : (
                  <div className="compact-records">
                    {data.assessments.map((assessment) => (
                      <article key={assessment.id}><header><strong>{formatEnumLabel(assessment.stage)}</strong><OperationalTag value={assessment.status} /></header><p>{assessment.intent}</p><small>{assessment.incidentTitle} · {assessment.technique_ids.join(", ") || "No mapped techniques"}</small></article>
                    ))}
                  </div>
                )}
              </OperationalSection>
              <OperationalSection title="Attack Chains" count={data.chains.length}>
                {data.chains.length === 0 ? <EmptyOperationalState icon={<ListTree size={24} />} label="No attack chains" /> : (
                  <div className="compact-records">
                    {data.chains.map((chain) => (
                      <article key={chain.id}><header><strong>Attack chain v{chain.version}</strong><OperationalTag value={chain.status} /></header><p>{chain.summary}</p><small>{chain.incidentTitle} · {chain.steps.length} reconstructed steps</small></article>
                    ))}
                  </div>
                )}
              </OperationalSection>
            </div>
          </TabPane>
          <TabPane itemKey="profiles" tab={<TabLabel icon={<UserRoundSearch size={15} />} text={`Profiles & Risk (${data.profiles.length + data.risks.length})`} />}>
            <div className="workspace-split">
              <OperationalSection title="Attacker Profiles" count={data.profiles.length}>
                {data.profiles.length === 0 ? <EmptyOperationalState icon={<UserRoundSearch size={24} />} label="No attacker profiles" /> : (
                  <div className="compact-records">
                    {data.profiles.map((profile) => (
                      <article key={profile.id}>
                        <header><strong>{profile.incidentTitle}</strong><OperationalTag value={profile.status} /></header>
                        <p>{profile.summary}</p>
                        <small>{formatEnumLabel(profile.confidence)} confidence · {profile.skill_level || "unknown skill"} · {profile.tools.join(", ") || "no tools attributed"}</small>
                      </article>
                    ))}
                  </div>
                )}
              </OperationalSection>
              <OperationalSection title="Risk Assessments" count={data.risks.length}>
                {data.risks.length === 0 ? <EmptyOperationalState icon={<Gauge size={24} />} label="No risk assessments" /> : (
                  <div className="compact-records">
                    {data.risks.map((risk) => (
                      <article key={risk.id}>
                        <header><strong>{risk.incidentTitle}</strong><OperationalTag value={risk.severity} /></header>
                        <p>{risk.rationale}</p>
                        <small>Risk {risk.risk_score}/100 · {risk.response_recommendations.length} response recommendations · {risk.defense_improvements.length} defense improvements</small>
                      </article>
                    ))}
                  </div>
                )}
              </OperationalSection>
            </div>
          </TabPane>
        </Tabs>
      </AsyncContent>
    </section>
  );
}
