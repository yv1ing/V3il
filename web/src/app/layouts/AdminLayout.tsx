import { Avatar, Button } from "@douyinfe/semi-ui";
import { Activity, LogOut } from "lucide-react";
import { ReactNode, Suspense, useCallback, useMemo, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate, useOutletContext } from "react-router-dom";
import { SessionList } from "../../features/playground/SessionList";
import v3ilLogo from "../../assets/v3il-logo.png";
import { useAgentSessionContext } from "../../features/playground/AgentSessionProvider";
import { useAuth } from "../../shared/auth/AuthProvider";
import { SYSTEM_USER_ROLE } from "../../shared/api/generated/constants";
import { cx } from "../../shared/lib/className";
import { adminNavigationRoutes } from "../routeManifest";
import { LOGIN_PATH } from "../routePaths";
import { preloadAdminRoute } from "../routePreload";

type AdminLayoutContext = {
  setHeaderActions: (actions: ReactNode) => void;
};

export function useAdminHeaderActions() {
  return useOutletContext<AdminLayoutContext>().setHeaderActions;
}

export function AdminLayout() {
  const { signOut, user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [headerActions, setHeaderActionsState] = useState<ReactNode>(null);
  const {
    sessions,
    sessionsLoading,
    sessionsLoadingMore,
    sessionsHasMore,
    activeSessionId,
    selectSession,
    deleteSession,
    refreshSessions,
    loadMoreSessions,
  } = useAgentSessionContext();

  const setHeaderActions = useCallback((actions: ReactNode) => {
    setHeaderActionsState((current) => (Object.is(current, actions) ? current : actions));
  }, []);

  const handleSelectAgentSession = useCallback((sessionId: string) => {
    selectSession(sessionId);
    if (!location.pathname.startsWith("/playground")) {
      navigate("/playground");
    }
  }, [location.pathname, navigate, selectSession]);

  const outletContext = useMemo<AdminLayoutContext>(
    () => ({ setHeaderActions }),
    [setHeaderActions],
  );

  const handleSignOut = () => {
    signOut();
    navigate(LOGIN_PATH, { replace: true });
  };

  const isAdmin = user?.role === SYSTEM_USER_ROLE.ADMIN;
  const visibleNavItems = adminNavigationRoutes.filter((item) => !item.adminOnly || isAdmin);
  const activeItem = visibleNavItems.find((item) => location.pathname.startsWith(item.path));
  const ActiveIcon = activeItem?.icon ?? Activity;
  const contentMode = location.pathname.startsWith("/playground") ? "fixed" : "contained";
  const navigationGroups = ["Operations", "Analysis", "Infrastructure", "Administration"] as const;

  return (
    <div className="admin-shell">
      <aside className="admin-sidebar">
        <div className="brand-lockup">
          <img className="brand-logo" src={v3ilLogo} alt="" aria-hidden="true" />
          <div>
            <div className="brand-name">V3il</div>
            <div className="brand-kicker">Autonomous Defense System</div>
          </div>
        </div>

        <div className="admin-sidebar-body">
          <nav className="admin-nav" aria-label="Primary navigation">
            {navigationGroups.map((group) => {
              const items = visibleNavItems.filter((item) => item.group === group);
              if (items.length === 0) return null;
              return (
                <div className="admin-nav-group" key={group}>
                  <div className="admin-nav-group-label">{group}</div>
                  {items.map((item) => {
                    const Icon = item.icon;
                    return (
                      <NavLink
                        key={item.path}
                        to={item.path}
                        className="admin-nav-link"
                        onFocus={() => preloadAdminRoute(item.path)}
                        onPointerDown={() => preloadAdminRoute(item.path)}
                        onPointerEnter={() => preloadAdminRoute(item.path)}
                      >
                        <Icon size={17} />
                        <div className="admin-nav-copy">
                          <span>{item.label}</span>
                          <small>{item.eyebrow}</small>
                        </div>
                      </NavLink>
                    );
                  })}
                </div>
              );
            })}
          </nav>
          <section className="admin-session-panel">
            <div className="admin-nav-group-label">Recent Sessions</div>
            <SessionList
              sessions={sessions}
              loading={sessionsLoading}
              loadingMore={sessionsLoadingMore}
              hasMore={sessionsHasMore}
              activeSessionId={activeSessionId}
              onSelect={handleSelectAgentSession}
              onDelete={deleteSession}
              onRefreshSessions={refreshSessions}
              onLoadMoreSessions={loadMoreSessions}
            />
          </section>
        </div>
      </aside>

      <div className="admin-main">
        <header className="admin-topbar">
          <div className="admin-topbar-title">
            <span className="admin-module-icon"><ActiveIcon size={20} /></span>
            <div>
              <div className="page-eyebrow">{activeItem?.eyebrow || "Operations"}</div>
              <h1>{activeItem?.label || "Console"}</h1>
            </div>
          </div>
          <div className="admin-topbar-utilities">
            {headerActions ? <div className="admin-topbar-operations">{headerActions}</div> : null}
            <div className="admin-topbar-session">
              <span className="admin-control-state"><i /> Online</span>
              <div className="admin-user-identity">
                <Avatar size="small" color="green">{user?.username?.[0]?.toUpperCase() || "U"}</Avatar>
                <span><strong>{user?.username || "User"}</strong><small>{user?.role || "operator"}</small></span>
              </div>
              <Button icon={<LogOut size={16} />} theme="borderless" type="tertiary" onClick={handleSignOut} aria-label="Sign out" />
            </div>
          </div>
        </header>
        <main className="admin-content">
          <div className={cx("admin-content-viewport", `admin-content-viewport-${contentMode}`)}>
            <div className={cx("admin-route", `admin-route-${contentMode}`)}>
              <Suspense fallback={<AdminRouteFallback />}>
                <Outlet context={outletContext} />
              </Suspense>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

function AdminRouteFallback() {
  return (
    <div className="admin-route-fallback">
      <div className="route-fallback-spinner" />
    </div>
  );
}
