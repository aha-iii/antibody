import { useCallback, useEffect, useState } from "react";
import { NerveAlert } from "@nerve/ui";
import { api, type Health, type PackInfo } from "./api";
import { getAuthMode, getUsername, initAuth, logout, type AuthPhase } from "./auth";
import { DashboardLayout } from "./layout/DashboardLayout";
import { PAGE_META, type PageId } from "./nav";
import { LoginPage } from "./pages/LoginPage";
import { BenchPage } from "./pages/BenchPage";
import {
  AdmissionPage,
  AlgorithmPage,
  LevelPage,
  OverviewPage,
  PacksPage,
  SemanticPage,
} from "./pages/ConfigPages";
import { EnginePage } from "./pages/EnginePage";
import { MetricsPage } from "./pages/MetricsPage";
import { SamplesPage } from "./pages/SamplesPage";
import { ShadowPage } from "./pages/ShadowPage";
import { VpPage } from "./pages/VpPage";

export function App() {
  const [authPhase, setAuthPhase] = useState<AuthPhase>("loading");
  const [page, setPage] = useState<PageId>("overview");
  const [health, setHealth] = useState<Health | null>(null);
  const [packs, setPacks] = useState<PackInfo[]>([]);
  const [bootError, setBootError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void initAuth()
      .then((phase) => {
        if (!cancelled) setAuthPhase(phase);
      })
      .catch(() => {
        if (!cancelled) setAuthPhase("ready");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const refresh = useCallback(async () => {
    const [h, p] = await Promise.all([api.health(), api.packs()]);
    setHealth(h);
    setPacks(p);
    setBootError(null);
  }, []);

  useEffect(() => {
    if (authPhase !== "ready") return;
    refresh().catch((e: unknown) => {
      setBootError(e instanceof Error ? e.message : String(e));
    });
  }, [authPhase, refresh]);

  if (authPhase === "loading") {
    return <div className="login-page muted">加载中…</div>;
  }

  if (authPhase === "login") {
    return <LoginPage onSuccess={() => setAuthPhase("ready")} />;
  }

  const healthText = health
    ? `${health.pack} · ${health.rule_count} rules`
    : bootError
      ? bootError
      : "connecting…";

  const shared = {
    health,
    packs,
    onRefresh: refresh,
  };

  const userLabel =
    getAuthMode() === "local" ? getUsername() || "user" : null;

  return (
    <DashboardLayout
      page={page}
      onNavigate={setPage}
      healthText={healthText}
      healthOk={bootError ? false : health?.ready}
      username={userLabel}
      onLogout={getAuthMode() === "local" ? () => void logout() : undefined}
    >
      {bootError && page === "overview" ? (
        <NerveAlert tone="error" style={{ marginBottom: 16 }}>
          无法连接专家引擎 API：{bootError}。请先{" "}
          <code>cargo run -p nerve-waf-native-dashboard</code>
        </NerveAlert>
      ) : null}

      {page === "overview" ? <OverviewPage {...shared} /> : null}
      {page === "packs" ? <PacksPage {...shared} /> : null}
      {page === "level" ? <LevelPage {...shared} /> : null}
      {page === "semantic" ? <SemanticPage {...shared} /> : null}
      {page === "algorithm" ? <AlgorithmPage {...shared} /> : null}
      {page === "admission" ? <AdmissionPage {...shared} /> : null}

      {page === "samples" ? (
        <SamplesPage
          health={health}
          packs={packs}
          onHealth={setHealth}
          onPacksRefresh={refresh}
        />
      ) : null}

      {page === "bench" ? <BenchPage health={health} /> : null}

      {page === "metrics" ? <MetricsPage health={health} /> : null}
      {page === "shadow" ? <ShadowPage health={health} /> : null}
      {page === "vp" ? <VpPage health={health} /> : null}

      {page === "engine" ? (
        <EnginePage
          health={health}
          packs={packs}
          bootError={bootError}
          onRefresh={refresh}
        />
      ) : null}

      <div className="muted small" style={{ marginTop: 24 }}>
        {PAGE_META[page].title} · Nerve Native Dashboard
      </div>
    </DashboardLayout>
  );
}
