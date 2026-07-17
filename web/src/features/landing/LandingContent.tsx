import type { ReactNode } from "react";
import {
  Activity,
  ArrowRight,
  Boxes,
  Braces,
  CircleDot,
  ClipboardCheck,
  Crosshair,
  Database,
  FileCheck2,
  FileSearch,
  FolderKanban,
  GitBranch,
  Layers3,
  LockKeyhole,
  Network,
  PackageCheck,
  Radio,
  Route,
  Server,
  ShieldCheck,
  SquareTerminal,
  UsersRound,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import {
  EGRESS_PROXY_TYPE_VALUES,
  SANDBOX_CONTAINER_EGRESS_MODE,
} from "../../shared/api/generated/constants";
import { cx } from "../../shared/lib/className";
import { formatEnumLabel } from "../../shared/lib/labels";
import { landingDocsOverviewUrl, landingRepositoryUrl } from "./landingConfig";

const egressModes = [
  formatEnumLabel(SANDBOX_CONTAINER_EGRESS_MODE.DIRECT),
  ...EGRESS_PROXY_TYPE_VALUES.map((type) => type.toUpperCase()),
  formatEnumLabel(SANDBOX_CONTAINER_EGRESS_MODE.TOR),
];

const operationSignals = [
  { label: "Deception", detail: "Shape attacker-visible services", code: "ADAPT", icon: Layers3 },
  { label: "Detection", detail: "Correlate behavior and policy signals", code: "DETECT", icon: Radio },
  { label: "Investigation", detail: "Turn evidence into response", code: "RESOLVE", icon: FileSearch },
];

type LandingPrimaryAction = {
  label: string;
  href?: string;
  external?: boolean;
  onSelect?: () => void;
};

type LandingContentProps = {
  logoSrc: string;
  primaryAction: LandingPrimaryAction;
};

type CardItem = {
  title: string;
  text: string;
  icon: LucideIcon;
  kicker?: string;
  items?: string[];
};

type AgentItem = {
  code: string;
  name: string;
  role: string;
  detail: string;
  icon: LucideIcon;
};

const planes: CardItem[] = [
  {
    title: "Operations Workbench",
    kicker: "Operator",
    text: "Keeps environments, Incidents, detections, intelligence, Agent work, and infrastructure in the same operating view.",
    icon: Activity,
    items: ["Shared context", "Operator decisions", "Operational visibility"],
  },
  {
    title: "Control and Orchestration",
    kicker: "Coordination",
    text: "Coordinates resources, workflows, Agent responsibilities, recovery, and review across the platform.",
    icon: Braces,
    items: ["Resource lifecycle", "Task coordination", "Human oversight"],
  },
  {
    title: "Deception Runtime",
    kicker: "Observation surface",
    text: "Runs believable attacker-facing environments and evolves them as the investigation raises new questions.",
    icon: Boxes,
    items: ["Environment design", "Versioned change", "Controlled exposure"],
  },
  {
    title: "Incident and Evidence",
    kicker: "ThreatIncident",
    text: "Connects behavior, investigation tasks, evidence, analytical history, environment changes, risk decisions, and reporting.",
    icon: FileCheck2,
    items: ["Behavior timeline", "Reviewable analysis", "Intelligence delivery"],
  },
];

const runtimePath: CardItem[] = [
  {
    title: "Design the surface",
    text: "Define the business context, attacker-facing services, identities, data, and observation goals.",
    icon: FolderKanban,
  },
  {
    title: "Launch and observe",
    text: "Deploy a versioned environment and begin collecting behavior and detection signals.",
    icon: Layers3,
  },
  {
    title: "Correlate activity",
    text: "Group related actions across environments into a shared ThreatIncident timeline.",
    icon: GitBranch,
  },
  {
    title: "Investigate",
    text: "Coordinate specialist work around scoped questions, evidence, and review.",
    icon: UsersRound,
  },
  {
    title: "Adapt or deliver",
    text: "Change the environment to test a hypothesis, or turn the findings into response guidance and reporting.",
    icon: Route,
  },
];

const evidenceNodes: CardItem[] = [
  { title: "Behavior timeline", text: "Attacker interaction retains source, time, environment, and surrounding context", icon: Activity },
  { title: "Incident context", text: "Related behavior and environments stay connected throughout the operation", icon: GitBranch },
  { title: "Scoped questions", text: "Investigation tasks define ownership, evidence needs, and completion criteria", icon: ClipboardCheck },
  { title: "Evidence", text: "Analytical statements point back to the behavior that supports them", icon: FileCheck2 },
  { title: "Versioned analysis", text: "Intent, attack chain, indicators, profile, and risk preserve their history", icon: FileSearch },
  { title: "Delivery", text: "Reviewed conclusions become response guidance, reports, evidence packages, and knowledge", icon: PackageCheck },
];

const workbenchSurfaces: CardItem[] = [
  { title: "Command Center", text: "Monitor the current state of environments, Incidents, detections, Agent work, and infrastructure.", icon: Activity },
  { title: "Deception Environments", text: "Design and operate attacker-facing environments with clear version history.", icon: Boxes },
  { title: "Incident Workspace", text: "Investigate behavior, evidence, analysis, environment changes, decisions, and reports in context.", icon: Crosshair },
  { title: "Detection", text: "Develop and operate Zeek and behavior detection policy.", icon: Radio },
  { title: "Threat Intelligence", text: "Review indicators, attacker profiles, risk, and intelligence reports.", icon: FileSearch },
  { title: "Agent Operations", text: "Track ownership, specialist work, coordination, and review.", icon: Workflow },
  { title: "Knowledge Base", text: "Retrieve prior reports, research, and related security context.", icon: Database },
  { title: "Infrastructure", text: "Operate the hosts, images, containers, network routes, terminals, and files behind the platform.", icon: Server },
];

const platformCapabilities: CardItem[] = [
  {
    title: "Environment design",
    text: "Turn business context, observation goals, and reference material into a credible attacker-facing surface.",
    icon: FolderKanban,
    items: ["Services and identities", "Realistic data", "Observation goals"],
  },
  {
    title: "Versioned operations",
    text: "Keep the purpose, risk, outcome, and history of each environment change visible to the team.",
    icon: ClipboardCheck,
    items: ["Planned change", "Verification", "Rollback context"],
  },
  {
    title: "Behavior visibility",
    text: "Follow attacker activity across network, host, identity, service, and outbound behavior.",
    icon: Activity,
    items: ["Shared timeline", "Source context", "Cross-environment view"],
  },
  {
    title: "Detection engineering",
    text: "Develop Zeek and behavior policy, deploy versions, and review decisions alongside the activity they describe.",
    icon: Radio,
    items: ["Zeek policy", "Behavior rules", "Detection outcomes"],
  },
  {
    title: "Adaptive engagement",
    text: "Change the environment around an investigative question and observe the attacker's response.",
    icon: Layers3,
    items: ["Hypothesis testing", "Operator approval", "Continuous observation"],
  },
  {
    title: "Reviewable delivery",
    text: "Carry evidence and analytical history into response guidance, reports, export, and searchable knowledge.",
    icon: PackageCheck,
    items: ["Response guidance", "Evidence package", "Knowledge reuse"],
  },
];

const agents: AgentItem[] = [
  { code: "cso", name: "V3il", role: "Chief Security Officer", detail: "Plans the investigation, coordinates specialists, reviews conclusions, and manages Incident progress.", icon: Workflow },
  { code: "cth", name: "H4wk", role: "Threat Investigation Engineer", detail: "Reconstructs behavior, timelines, attack paths, and intent from the available evidence.", icon: FileSearch },
  { code: "cde", name: "Ph4ntom", role: "Deception Defense Engineer", detail: "Designs and adapts environments to support observation and hypothesis testing.", icon: Layers3 },
  { code: "cie", name: "L1ly", role: "Cyber Threat Intelligence Engineer", detail: "Develops indicators, external context, attacker profiles, and attribution limits.", icon: Database },
  { code: "cir", name: "J4ck", role: "Security Response Engineer", detail: "Assesses risk, stop conditions, response priorities, and defensive improvements.", icon: ShieldCheck },
];

export function LandingContent({ logoSrc, primaryAction }: LandingContentProps) {
  return (
    <main className="landing-page">
      <div className="landing-grid" aria-hidden="true" />
      <div className="landing-scanline" aria-hidden="true" />

      <section className="landing-hero" aria-label="V3il landing page">
        <div className="landing-hero-copy">
          <img className="landing-hero-logo" src={logoSrc} width="1000" height="1000" alt="V3il logo" />
          <span className="page-eyebrow">Open-source autonomous blue-team operations platform</span>
          <p>V3il turns controlled attacker interaction into a structured investigation. Shape the environment, follow the evidence, and decide what to do next from the same operational context.</p>
          <div className="landing-actions">
            <ActionLink action={primaryAction} primary />
            <ActionLink action={{ label: "GitHub", href: landingRepositoryUrl, external: true }} icon={GitBranch} ghost />
          </div>
        </div>
        <OperationMeshPanel />
      </section>

      <Section
        eyebrow="Product architecture"
        title="Clear boundaries, shared operational context."
        description="The workbench, orchestration layer, deception runtime, and Incident model each have a focused role. Their shared context keeps environment changes, attacker behavior, evidence, and decisions connected."
      >
        <div className="landing-card-grid landing-card-grid-4">
          {planes.map((item) => <Card key={item.title} item={item} accent />)}
        </div>
      </Section>

      <Section eyebrow="Core workflow" title="The environment, investigation, and response move through the same operating model.">
        <div className="landing-card-grid landing-card-grid-5">
          {runtimePath.map((item, index) => <Card key={item.title} item={item} index={index} arrow={index < runtimePath.length - 1} />)}
        </div>
      </Section>

      <Section
        eyebrow="Investigation model"
        title="ThreatIncident keeps the operation coherent as the evidence changes."
        description="Behavior, questions, evidence, analytical history, environment adaptations, and decisions stay in the same case record from first observation through final delivery."
      >
        <div className="landing-card-grid landing-card-grid-6">
          {evidenceNodes.map((item, index) => <Card key={item.title} item={item} index={index} arrow={index < evidenceNodes.length - 1} />)}
        </div>
      </Section>

      <Section eyebrow="Deception fabric" title="Run the observation surface where it fits the operation.">
        <div className="landing-sandbox-topology">
          <SandboxNetworkMap />
          <div className="landing-panel landing-topology-copy">
            <h3>Managed Hosts provide a consistent operating model across isolated environments.</h3>
            <p>Operators choose where an environment runs, which image it uses, how it reaches the network, and how changes are approved. Ph4ntom designs the attacker-facing surface within those boundaries.</p>
            <p>Behavior and detection signals return to the same Incident workflow regardless of host or egress route, so distributed environments remain part of one investigation.</p>
          </div>
        </div>
      </Section>

      <Section
        eyebrow="Platform capabilities"
        title="Purpose-built for deception-led investigation."
        description="V3il connects environment design, behavior visibility, detection, adaptive engagement, evidence, and delivery without losing the context between them."
      >
        <div className="landing-card-grid landing-card-grid-3">
          {platformCapabilities.map((item) => <Card key={item.title} item={item} accent />)}
        </div>
      </Section>

      <Section eyebrow="Operator workbench" title="Move between live operations and deep investigation without rebuilding context.">
        <div className="landing-card-grid landing-card-grid-3">
          {workbenchSurfaces.map((item) => <Card key={item.title} item={item} />)}
        </div>
      </Section>

      <Section eyebrow="Specialist team" title="Five roles bring different judgment to the same Incident.">
        <div className="landing-card-grid landing-card-grid-3">
          {agents.map((agent) => <AgentCard key={agent.code} agent={agent} />)}
        </div>
      </Section>

      <Section className="landing-security" eyebrow="Operational boundary" title="Built for authorized, isolated environments.">
        <div className="landing-panel landing-boundary">
          <p>Deploy V3il with explicit authority, dedicated infrastructure, a trusted management network, and clear controls for sensitive data, evidence retention, and environment disposal.</p>
          <a className="landing-inline-link" href={landingDocsOverviewUrl} target="_blank" rel="noopener noreferrer">
            Read the documentation
            <ArrowRight size={16} />
          </a>
        </div>
      </Section>
    </main>
  );
}

function Section({
  children,
  className = "",
  description,
  eyebrow,
  title,
}: {
  children: ReactNode;
  className?: string;
  description?: string;
  eyebrow: string;
  title: string;
}) {
  return (
    <section className={cx("landing-section", className)}>
      <div className="landing-section-heading">
        <span className="page-eyebrow">{eyebrow}</span>
        <h2>{title}</h2>
        {description ? <p>{description}</p> : null}
      </div>
      {children}
    </section>
  );
}

function OperationMeshPanel() {
  return (
    <div className="landing-ops-panel" aria-label="Autonomous blue-team collaboration model">
      <div className="landing-ops-panel-heading">
        <div>
          <span className="page-eyebrow">Investigation team</span>
          <h2>One Incident, five perspectives, shared evidence.</h2>
        </div>
        <span className="landing-live-status"><i /> Investigation active</span>
      </div>

      <div className="landing-ops-console">
        <div className="landing-ops-commandbar">
          <span><SquareTerminal size={15} /> INCIDENT / ACTIVE</span>
          <span><Radio size={14} /> LIVE BEHAVIOR</span>
        </div>

        <div className="landing-ops-overview">
          <div className="landing-target-pane">
            <div className="landing-console-label">
              <span><Crosshair size={14} /> Deception surface</span>
              <strong>Observation live</strong>
            </div>
            <div className="landing-target-radar" aria-hidden="true">
              <i className="landing-radar-ring landing-radar-ring-1" />
              <i className="landing-radar-ring landing-radar-ring-2" />
              <i className="landing-radar-axis landing-radar-axis-x" />
              <i className="landing-radar-axis landing-radar-axis-y" />
              <i className="landing-radar-sweep" />
              <i className="landing-radar-pip landing-radar-pip-1" />
              <i className="landing-radar-pip landing-radar-pip-2" />
              <i className="landing-radar-pip landing-radar-pip-3" />
              <Crosshair size={26} />
            </div>
            <div className="landing-target-states">
              <span><i /> Surface active</span>
              <span><i /> Evidence linked</span>
            </div>
          </div>

          <div className="landing-signal-pane">
            <div className="landing-console-label">
              <span><Activity size={14} /> Investigation flow</span>
              <strong>Correlated</strong>
            </div>
            <div className="landing-signal-list">
              {operationSignals.map(({ code, detail, icon: Icon, label }) => (
                <div className="landing-signal-row" key={label}>
                  <Icon size={17} />
                  <div>
                    <strong>{label}</strong>
                    <span>{detail}</span>
                  </div>
                  <small>{code}</small>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="landing-ops-agent-mesh">
          <div className="landing-console-label">
            <span><UsersRound size={14} /> Specialist relay</span>
            <strong>Shared context</strong>
          </div>
          <div className="landing-ops-agent-network">
            <div className="landing-ops-lead-node">
              <Workflow size={18} />
              <span><strong>{agents[0].code}</strong> investigation lead</span>
            </div>
            <div className="landing-ops-specialists">
              {agents.slice(1).map(({ code, icon: Icon, role }) => (
                <div className="landing-ops-specialist" key={code} title={role}>
                  <Icon size={16} />
                  <strong>{code}</strong>
                  <span>{role.replace(" Engineer", "")}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="landing-community-strip">
          <span><GitBranch size={15} /> Open-source core</span>
          <span><Layers3 size={15} /> Adaptive deception</span>
          <span><LockKeyhole size={15} /> Evidence integrity</span>
          <span><FileCheck2 size={15} /> Auditable decisions</span>
        </div>
      </div>
    </div>
  );
}

function SandboxNetworkMap() {
  const managedNodes = [
    { name: "Managed Host 01", workload: "Active environment", icon: SquareTerminal },
    { name: "Managed Host 02", workload: "Detection coverage", icon: Radio },
  ];

  return (
    <div className="landing-topology-map" aria-label="Distributed deception and egress topology">
      <div className="landing-network-heading">
        <span><Network size={15} /> Managed environment fabric</span>
        <strong><i /> Operations ready</strong>
      </div>

      <div className="landing-network-canvas">
        <div className="landing-network-control">
          <span className="landing-network-kicker">Design</span>
          <div className="landing-network-primary-node">
            <FolderKanban size={20} />
            <strong>Observation plan</strong>
            <span>Context + goals</span>
          </div>
          <div className="landing-network-tags">
            <span>Runtime selected</span>
            <span>Policy selected</span>
          </div>
        </div>

        <NetworkConnector label="deploy" />

        <div className="landing-host-fabric">
          <div className="landing-host-fabric-heading">
            <span><Server size={15} /> Managed host pool</span>
            <small>Capacity ready</small>
          </div>
          <div className="landing-host-grid">
            {managedNodes.map(({ icon: Icon, name, workload }) => (
              <div className="landing-host-node" key={name}>
                <div>
                  <Server size={16} />
                  <strong>{name}</strong>
                  <i />
                </div>
                <span><Icon size={14} /> {workload}</span>
                <small>Isolated runtime</small>
              </div>
            ))}
          </div>
        </div>

        <NetworkConnector label="policy" />

        <div className="landing-network-egress">
          <span className="landing-network-kicker">Egress</span>
          <div className="landing-egress-gateway">
            <Route size={19} />
            <strong>Route gateway</strong>
            <span>Controlled route</span>
          </div>
          <div className="landing-egress-modes">
            {egressModes.map((mode) => <span key={mode}>{mode}</span>)}
          </div>
        </div>
      </div>

      <div className="landing-community-rail">
        <span><FolderKanban size={15} /> Design context</span>
        <ArrowRight size={14} aria-hidden="true" />
        <span><PackageCheck size={15} /> Environment version</span>
        <ArrowRight size={14} aria-hidden="true" />
        <span><Activity size={15} /> Behavior timeline</span>
      </div>
    </div>
  );
}

function NetworkConnector({ label }: { label: string }) {
  return (
    <div className="landing-network-connector" aria-hidden="true">
      <span>{label}</span>
      <i />
      <CircleDot size={11} />
    </div>
  );
}

function Card({ accent = false, arrow, index, item }: { accent?: boolean; arrow?: boolean; index?: number; item: CardItem }) {
  const Icon = item.icon;
  return (
    <article className={cx("landing-card", accent && "landing-card-accent")}>
      <div className="landing-card-topline">
        <span>{item.kicker ?? (index != null ? String(index + 1).padStart(2, "0") : "Module")}</span>
        <Icon size={20} />
      </div>
      <h3>{item.title}</h3>
      <p>{item.text}</p>
      {item.items ? <ul>{item.items.map((entry) => <li key={entry}>{entry}</li>)}</ul> : null}
      {arrow ? <ArrowRight className="landing-card-arrow" size={18} aria-hidden="true" /> : null}
    </article>
  );
}

function AgentCard({ agent }: { agent: AgentItem }) {
  const Icon = agent.icon;
  return (
    <article className="landing-card landing-card-agent">
      <div className="landing-card-topline">
        <span>{agent.code}</span>
        <Icon size={18} />
      </div>
      <span className="landing-agent-state"><i /> Specialist profile</span>
      <strong>{agent.name}</strong>
      <h3>{agent.role}</h3>
      <p>{agent.detail}</p>
    </article>
  );
}

function ActionLink({ action, ghost = false, icon: Icon = ShieldCheck, primary = false }: {
  action: LandingPrimaryAction;
  ghost?: boolean;
  icon?: LucideIcon;
  primary?: boolean;
}) {
  const className = cx(
    "landing-action-link",
    primary ? "landing-action-primary" : ghost ? "landing-action-ghost" : "landing-action-secondary",
  );

  const content = (
    <>
      <Icon size={17} />
      <span>{action.label}</span>
    </>
  );

  if (action.href) {
    return (
      <a className={className} href={action.href} target={action.external ? "_blank" : undefined} rel={action.external ? "noopener noreferrer" : undefined}>
        {content}
      </a>
    );
  }

  return <button className={className} type="button" onClick={action.onSelect}>{content}</button>;
}
