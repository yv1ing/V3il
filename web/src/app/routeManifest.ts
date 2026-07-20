import {
  Activity,
  Bot,
  BookOpenText,
  Box,
  Boxes,
  FileSearch,
  MessageSquareCode,
  Network,
  Radar,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Users,
  type LucideIcon,
} from "lucide-react";
import { lazy, type ComponentType, type LazyExoticComponent } from "react";
import { AGENT_CONSOLE_PATH, DEFAULT_ADMIN_PATH } from "./routePaths";

type AdminRoute = {
  path: string;
  label: string;
  eyebrow: string;
  icon: LucideIcon;
  adminOnly: boolean;
  navigation: boolean;
  group: "Operations" | "Analysis" | "Infrastructure" | "Administration";
  loader: () => Promise<unknown>;
  component: LazyExoticComponent<ComponentType>;
};

type RouteMetadata = Omit<AdminRoute, "component" | "loader">;

function defineRoute<TModule, TKey extends keyof TModule>(
  metadata: RouteMetadata,
  loader: () => Promise<TModule>,
  exportName: TKey,
): AdminRoute {
  return {
    ...metadata,
    loader,
    component: lazy(async () => ({
      default: (await loader())[exportName] as ComponentType,
    })),
  };
}

export const adminRoutes: readonly AdminRoute[] = [
  defineRoute(
    { path: DEFAULT_ADMIN_PATH, label: "Command Center", eyebrow: "Defense Overview", icon: Activity, adminOnly: false, navigation: true, group: "Operations" },
    () => import("../features/command-center/CommandCenterPage"),
    "CommandCenterPage",
  ),
  defineRoute(
    { path: "/incidents", label: "Incidents", eyebrow: "Threat Response", icon: ShieldAlert, adminOnly: false, navigation: true, group: "Operations" },
    () => import("../features/incidents/IncidentsPage"),
    "IncidentsPage",
  ),
  defineRoute(
    { path: "/incidents/:incidentId", label: "Incident Workspace", eyebrow: "Threat Investigation", icon: ShieldAlert, adminOnly: false, navigation: false, group: "Operations" },
    () => import("../features/incidents/IncidentWorkspacePage"),
    "IncidentWorkspacePage",
  ),
  defineRoute(
    { path: "/deception-environments", label: "Deception", eyebrow: "Adaptive Environments", icon: Radar, adminOnly: false, navigation: true, group: "Operations" },
    () => import("../features/deception/DeceptionEnvironmentsPage"),
    "DeceptionEnvironmentsPage",
  ),
  defineRoute(
    { path: "/deception-environments/:environmentId", label: "Deception Workspace", eyebrow: "Environment Control", icon: Radar, adminOnly: false, navigation: false, group: "Operations" },
    () => import("../features/deception/DeceptionWorkspacePage"),
    "DeceptionWorkspacePage",
  ),
  defineRoute(
    { path: AGENT_CONSOLE_PATH, label: "Agent Console", eyebrow: "Expert Collaboration", icon: MessageSquareCode, adminOnly: false, navigation: true, group: "Operations" },
    () => import("../features/playground/PlaygroundPage"),
    "PlaygroundPage",
  ),
  defineRoute(
    { path: `${AGENT_CONSOLE_PATH}/session/:sessionId`, label: "Agent Console", eyebrow: "Expert Collaboration", icon: MessageSquareCode, adminOnly: false, navigation: false, group: "Operations" },
    () => import("../features/playground/PlaygroundPage"),
    "PlaygroundPage",
  ),
  defineRoute(
    { path: "/agent-operations", label: "Agent Operations", eyebrow: "Autonomous Team", icon: Bot, adminOnly: false, navigation: true, group: "Analysis" },
    () => import("../features/agent-operations/AgentOperationsPage"),
    "AgentOperationsPage",
  ),
  defineRoute(
    { path: "/detection", label: "Detection", eyebrow: "Zeek & Rule Control", icon: ShieldCheck, adminOnly: false, navigation: true, group: "Analysis" },
    () => import("../features/detection/DetectionPage"),
    "DetectionPage",
  ),
  defineRoute(
    { path: "/threat-intelligence", label: "Threat Intelligence", eyebrow: "Evidence & Insights", icon: FileSearch, adminOnly: false, navigation: true, group: "Analysis" },
    () => import("../features/threat-intelligence/ThreatIntelligencePage"),
    "ThreatIntelligencePage",
  ),
  defineRoute(
    { path: "/knowledges", label: "Knowledge Base", eyebrow: "Defense Memory", icon: BookOpenText, adminOnly: true, navigation: true, group: "Analysis" },
    () => import("../features/knowledges/KnowledgesPage"),
    "KnowledgesPage",
  ),
  defineRoute(
    { path: "/hosts", label: "Managed Hosts", eyebrow: "Remote Capacity", icon: Server, adminOnly: true, navigation: true, group: "Infrastructure" },
    () => import("../features/hosts/HostsPage"),
    "HostsPage",
  ),
  defineRoute(
    { path: "/egress-proxies", label: "Egress Proxies", eyebrow: "Network Control", icon: Network, adminOnly: true, navigation: true, group: "Infrastructure" },
    () => import("../features/egress-proxies/EgressProxiesPage"),
    "EgressProxiesPage",
  ),
  defineRoute(
    { path: "/sandbox-images", label: "Runtime Images", eyebrow: "Container Baselines", icon: Boxes, adminOnly: true, navigation: true, group: "Infrastructure" },
    () => import("../features/sandbox-images/SandboxImagesPage"),
    "SandboxImagesPage",
  ),
  defineRoute(
    { path: "/sandbox-containers", label: "Runtime Containers", eyebrow: "Isolated Workloads", icon: Box, adminOnly: true, navigation: true, group: "Infrastructure" },
    () => import("../features/sandbox-containers/SandboxContainersPage"),
    "SandboxContainersPage",
  ),
  defineRoute(
    { path: "/system-users", label: "System Users", eyebrow: "Access Control", icon: Users, adminOnly: true, navigation: true, group: "Administration" },
    () => import("../features/system-users/SystemUsersPage"),
    "SystemUsersPage",
  ),
  defineRoute(
    { path: "/system-config", label: "System Config", eyebrow: "Runtime Policy", icon: Settings, adminOnly: true, navigation: true, group: "Administration" },
    () => import("../features/system-config/SystemConfigPage"),
    "SystemConfigPage",
  ),
];

export const adminNavigationRoutes = adminRoutes.filter((route) => route.navigation);
