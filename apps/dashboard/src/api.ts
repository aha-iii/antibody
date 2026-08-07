import { getAuthHeaders } from "./auth";

export type NativeLevel = "low" | "medium" | "high";

export type Health = {
  ready: boolean;
  pack_id: string;
  pack_version: string;
  content_hash: string;
  rule_count: number;
  block_threshold: number;
  threshold_low?: number;
  threshold_medium?: number;
  threshold_high?: number;
  rules_low?: number;
  rules_medium?: number;
  rules_high?: number;
  observe_only: boolean;
  semantic_enabled?: boolean;
  adaptive_enabled?: boolean;
  adaptive_contribute?: boolean;
  accel: string;
  pipeline_decode?: boolean;
  pipeline_structural?: boolean;
  pipeline_base64?: boolean;
  max_inspect_ms?: number;
  model_version?: string;
  inspect_mode?: string;
  fast_max_inspect_ms?: number | null;
  semantic_pack_path?: string | null;
  semantic_pack_version?: string | null;
  semantic_signature_count?: number;
  signals_enabled?: boolean;
  signals_pack_path?: string | null;
  signals_pack_version?: string | null;
  signals_feature_count?: number;
  signals_fingerprint_count?: number;
  pack: string;
  packs_root: string;
};

export type MetricsSnapshot = {
  inspect_total: number;
  inspect_fast: number;
  inspect_deep: number;
  inspect_hit: number;
  inspect_block: number;
  inspect_challenge: number;
  inspect_observe: number;
  budget_exhausted: number;
  latency_us_avg: number;
  latency_us_max: number;
  latency_fast_us_avg: number;
  latency_deep_us_avg: number;
  stage_decode_us_avg: number;
  stage_aho_us_avg: number;
  stage_regex_us_avg: number;
  stage_semantic_us_avg: number;
  stage_fusion_us_avg: number;
  route_gate_deep_ratio: number;
  latency_buckets: number[];
  top_rules: Array<{ rule_id: string; hits: number }>;
  shadow_done: number;
  shadow_would_hit: number;
  shadow_dropped: number;
  fast_pool_escalate: number;
  fast_ratio?: number;
};

export type ShadowSample = {
  uri: string;
  would_hit: boolean;
  action: string;
  total_score: number;
  rule_id: string;
};

export type ShadowFeedback = {
  uri: string;
  label: string;
  note: string;
  created_ms: number;
  matched_rule_id?: string | null;
};

export type PackInfo = {
  id: string;
  path: string;
  current: boolean;
};

export type MatchedRule = {
  rule_id: string;
  rule_name: string;
  severity: string;
  score: number;
  action: string;
  evidence: string;
};

export type NativeHit = {
  total_score: number;
  block_threshold: number;
  action: string;
  matched: MatchedRule[];
  rule_id: string;
  rule_name: string;
  severity: string;
  evidence: string;
  level?: string;
  rule_score?: number;
  allow_score?: number;
  semantic_score?: number;
  model_score?: number;
  semantic_signals?: Array<{
    kind: string;
    id: string;
    confidence: number;
    score_delta: number;
    veto: boolean;
    evidence: string;
  }>;
  model?: {
    p: number;
    model_score: number;
    contributed: boolean;
    version: string;
    top_features: string[];
  } | null;
};

export type InspectResult = {
  hit: NativeHit | null;
  elapsed_ms: number;
  level: string;
  pack: string;
};

export type InspectPayload = {
  method: string;
  host: string;
  uri: string;
  query: string;
  headers: Record<string, string>;
  body: string;
  level: NativeLevel;
};

export type SampleRequest = {
  method: string;
  host: string;
  uri: string;
  query: string;
  headers: Record<string, string>;
  body: string;
};

export type SampleCase = {
  id: string;
  rule_id: string;
  name: string;
  category: string;
  expect_action: string;
  min_level: string;
  severity: string;
  tags: string[];
  request: SampleRequest;
};

export type SamplesOut = {
  pack: string;
  count: number;
  categories: string[];
  samples: SampleCase[];
};

export type BenchPhase = "idle" | "running" | "done" | "failed" | "stopped";

export type BenchMetrics = {
  total: number;
  success: number;
  error: number;
  malicious_total: number;
  blocked_ok: number;
  missed: number;
  normal_total: number;
  passed_ok: number;
  false_positive: number;
  detection_rate: number;
  false_positive_rate: number;
  accuracy: number;
  avg_ms: number;
  pass_count: number;
  fail_count: number;
  fast_path_count?: number;
  deep_path_count?: number;
  fast_path_ratio?: number;
  avg_fast_ms?: number;
  avg_deep_ms?: number;
  avg_ris_ms?: number;
  max_ms?: number;
  budget_exhausted_count?: number;
};

export type CaseResult = {
  index: number;
  id: string;
  suite: string;
  kind: string;
  name: string;
  request_summary: string;
  expect: string;
  actual: string;
  ok: boolean;
  elapsed_ms: number;
  rule_id: string;
  detail: string;
  inspect_path?: string;
  inspect_mode?: string;
  lane?: string;
  ris_zone?: string;
  ris_ms?: number;
  fast_ms?: number;
  deep_ms?: number;
  route_score?: number;
  route_deep?: boolean;
  budget_exhausted?: string;
  semantic_score?: number;
  model_score?: number;
};

export type BenchStatus = {
  phase: BenchPhase;
  pack: string;
  level: string;
  inspect_mode?: string;
  dataset: string;
  concurrency: number;
  timeout_ms: number;
  target: string;
  progress_pct: number;
  done: number;
  total: number;
  message: string;
  started_at_ms: number | null;
  finished_at_ms: number | null;
  elapsed_ms: number | null;
  metrics: BenchMetrics | null;
  blazehttp_bin: string;
  ready: boolean;
  ready_message: string;
  fail_count: number;
  pass_count: number;
};

export type BenchDatasetId =
  | "samples"
  | "samples-positive"
  | "samples-negative"
  | "blazehttp"
  | "blazehttp-regression"
  | "gotestwaf"
  | "waftester"
  | "crs-ftw";

export type BenchSampleExpect = "all" | "block" | "pass";

export type BenchDatasetInfo = {
  id: BenchDatasetId;
  label: string;
  description: string;
  ready: boolean;
  path: string;
  message: string;
  fetch_hint: string;
};

export type BenchStartBody = {
  dataset?: BenchDatasetId;
  concurrency?: number;
  level?: NativeLevel;
  /** auto（默认）| deep | fast */
  inspect_mode?: "auto" | "deep" | "fast";
  timeout_ms?: number;
  limit?: number;
  /** samples 极性：all | block（正）| pass（负）；亦可用 dataset samples-positive/negative */
  sample_expect?: BenchSampleExpect;
};

export type BenchResultsOut = {
  total: number;
  page: number;
  page_size: number;
  items: CaseResult[];
};

export type RisCurvePoint = {
  threshold: number;
  attack_fast_miss: number;
  clean_fast_ratio: number;
};

export type RisCalibrateReport = {
  recommended_deep_threshold: number;
  recommended_gray_threshold: number;
  attack_fast_miss: number;
  clean_fast_ratio: number;
  attack_count: number;
  clean_count: number;
  max_miss: number;
  curve: RisCurvePoint[];
  model: string;
};

export type RisCalibrateOut = {
  ok: boolean;
  report: RisCalibrateReport;
  wrote?: { weights?: string; curve?: string } | null;
  sample_count?: number;
  path?: string;
};

async function parse<T>(res: Response): Promise<T> {
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { error: text };
  }
  if (!res.ok) {
    const err =
      data && typeof data === "object" && "error" in data
        ? String((data as { error: unknown }).error)
        : res.statusText || String(res.status);
    throw new Error(err);
  }
  return data as T;
}

function authFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const headers = {
    ...getAuthHeaders(),
    ...(init?.headers as Record<string, string> | undefined),
  };
  return fetch(input, { ...init, headers });
}

export const api = {
  health: () => authFetch("/api/health").then((r) => parse<Health>(r)),
  packs: () => authFetch("/api/packs").then((r) => parse<PackInfo[]>(r)),
  samples: (params?: { pack?: string; category?: string; q?: string }) => {
    const sp = new URLSearchParams();
    if (params?.pack) sp.set("pack", params.pack);
    if (params?.category) sp.set("category", params.category);
    if (params?.q) sp.set("q", params.q);
    const qs = sp.toString();
    return authFetch(`/api/samples${qs ? `?${qs}` : ""}`).then((r) =>
      parse<SamplesOut>(r),
    );
  },
  reload: (pack: string) =>
    authFetch("/api/reload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pack }),
    }).then((r) => parse<Health>(r)),
  inspect: (payload: InspectPayload) =>
    authFetch("/api/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then((r) => parse<InspectResult>(r)),
  benchStatus: () =>
    authFetch("/api/bench/status").then((r) => parse<BenchStatus>(r)),
  benchDatasets: () =>
    authFetch("/api/bench/datasets").then((r) =>
      parse<{ items: BenchDatasetInfo[] }>(r),
    ),
  benchStart: (body: BenchStartBody = {}) =>
    authFetch("/api/bench/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => parse<BenchStatus>(r)),
  benchStop: () =>
    authFetch("/api/bench/stop", { method: "POST" }).then((r) =>
      parse<BenchStatus>(r),
    ),
  benchResults: (params?: {
    page?: number;
    page_size?: number;
    verdict?: string;
    kind?: string;
  }) => {
    const sp = new URLSearchParams();
    if (params?.page != null) sp.set("page", String(params.page));
    if (params?.page_size != null) sp.set("page_size", String(params.page_size));
    if (params?.verdict) sp.set("verdict", params.verdict);
    if (params?.kind) sp.set("kind", params.kind);
    const qs = sp.toString();
    return authFetch(`/api/bench/results${qs ? `?${qs}` : ""}`).then((r) =>
      parse<BenchResultsOut>(r),
    );
  },
  benchReport: () =>
    authFetch("/api/bench/report").then((r) => parse<Record<string, unknown>>(r)),

  risCalibrate: (body: {
    use_last_report?: boolean;
    max_miss?: number;
    use_stumps?: boolean;
    write_weights?: boolean;
    pack?: string;
  } = {}) =>
    authFetch("/api/ris/calibrate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => parse<RisCalibrateOut>(r)),
  risCurve: () =>
    authFetch("/api/ris/curve").then((r) => parse<RisCalibrateOut>(r)),

  overlay: () => authFetch("/api/overlay").then((r) => parse<ExpertOverlay>(r)),
  putOverlay: (body: ExpertOverlay) =>
    authFetch("/api/overlay", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => parse<ExpertOverlay>(r)),
  ruleSets: () => authFetch("/api/rule-sets").then((r) => parse<RuleSetsOut>(r)),
  rules: (params?: { set?: string }) => {
    const sp = new URLSearchParams();
    if (params?.set) sp.set("set", params.set);
    const qs = sp.toString();
    return authFetch(`/api/rules${qs ? `?${qs}` : ""}`).then((r) => parse<RulesOut>(r));
  },
  admission: () =>
    authFetch("/api/admission").then((r) => parse<AdmissionConfig>(r)),
  putAdmission: (body: AdmissionConfig) =>
    authFetch("/api/admission", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => parse<AdmissionConfig>(r)),

  metrics: () =>
    authFetch("/api/metrics").then((r) => parse<MetricsSnapshot>(r)),

  shadowRecent: () =>
    authFetch("/api/shadow/recent").then((r) =>
      parse<{ count: number; samples: ShadowSample[] }>(r),
    ),
  shadowFeedbackList: () =>
    authFetch("/api/shadow/feedback").then((r) =>
      parse<{ count: number; items: ShadowFeedback[] }>(r),
    ),
  shadowFeedback: (body: {
    uri: string;
    label: string;
    note?: string;
    rule_id?: string;
  }) =>
    authFetch("/api/shadow/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => parse<{ ok: boolean }>(r)),
  shadowExportRules: () =>
    authFetch("/api/shadow/export-rules").then(async (r) => {
      const text = await r.text();
      if (!r.ok) throw new Error(text || r.statusText);
      return text;
    }),

  vpList: () =>
    authFetch("/api/vp").then((r) => parse<VpListOut>(r)),
  vpStatus: () =>
    authFetch("/api/vp/status").then((r) => parse<VpStatus>(r)),
  vpSandbox: (cve_id: string) =>
    authFetch("/api/vp/sandbox", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cve_id }),
    }).then((r) => parse<VpStatus>(r)),
  vpPromote: (cve_id: string) =>
    authFetch("/api/vp/promote", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cve_id }),
    }).then((r) => parse<VpStatus>(r)),
  vpRollback: (cve_id: string) =>
    authFetch("/api/vp/rollback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cve_id }),
    }).then((r) => parse<VpStatus>(r)),
  vpImport: (source_path: string) =>
    authFetch("/api/vp/import", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source_path }),
    }).then((r) => parse<VpListOut>(r)),
  vpProbe: (query?: string) =>
    authFetch("/api/vp/probe", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(query != null ? { query } : {}),
    }).then((r) => parse<VpProbeOut>(r)),
  vpUpdatesCheck: () =>
    authFetch("/api/vp/updates/check").then((r) => parse<VpChannelCheck>(r)),
  vpUpdatesFetch: () =>
    authFetch("/api/vp/updates/fetch", { method: "POST" }).then((r) =>
      parse<VpFetchOut>(r),
    ),
  vpIngest: (item: VpIntelItem) =>
    authFetch("/api/vp/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(item),
    }).then((r) => parse<VpListOut>(r)),
};

export type VpEntry = {
  cve_id: string;
  path: string;
  title: string;
  severity: string;
  status: string;
  default_action: string;
  rule_count: number;
  sample_count: number;
};

export type VpListOut = {
  pack: string;
  items: VpEntry[];
};

export type VpStatus = {
  pack: string;
  pack_version: string;
  rule_count: number;
  sandbox_mounted: boolean;
  sandbox_pack_id: string | null;
  vp_live_count: number;
  vp_total: number;
};

export type VpProbeOut = {
  action: string;
  rule_id: string;
  inspect_path: string;
};

export type VpChannelCheck = {
  channel_url: string;
  track: string;
  remote_version: string;
  local_version: string;
  update_available: boolean;
  cve_added: string[];
  artifact_path: string;
  published_at: string | null;
};

export type VpFetchOut = {
  check: VpChannelCheck;
  imported: string[];
  sandbox_cve: string | null;
  promoted_live: boolean;
};

export type VpIntelItem = {
  cve_id: string;
  title?: string;
  severity?: string;
  match_contains: string;
  fields?: string[];
  source?: string;
  description?: string;
};

export type AdmissionConfig = {
  ddos: {
    enabled: boolean;
    action: string;
    global: {
      enabled: boolean;
      requests_per_second: number;
      burst: number;
    };
    ip: {
      enabled: boolean;
      requests_per_second: number;
      burst: number;
      window_sec: number;
      window_max_requests: number;
      block_duration_sec: number;
    };
    subnet: {
      enabled: boolean;
      prefix_v4: number;
      requests_per_second: number;
      window_sec: number;
    };
    concurrency: {
      enabled: boolean;
      max_concurrent_per_ip: number;
    };
    burst: {
      enabled: boolean;
      spike_factor: number;
      min_samples: number;
      ewma_alpha: number;
    };
    blocklist: {
      enabled: boolean;
      max_entries: number;
    };
    kernel_drop: {
      enabled: boolean;
      iface: string;
      min_score: number;
      dedup_ttl_sec: number;
      source: string;
    };
  };
  cc: {
    enabled: boolean;
    requests_per_minute: number;
    burst: number;
    block_duration_sec: number;
    action: string;
  };
  bot: {
    enabled: boolean;
    action: string;
    score_threshold: number;
  };
  geo: {
    enabled: boolean;
    block_countries: string[];
    allow_countries: string[];
    action: string;
    ip_country_overrides: Array<{ ip: string; country: string }>;
  };
};

export type ExpertOverlay = {
  level: NativeLevel | string;
  disabled_rule_ids: string[];
  disabled_categories: string[];
  semantic_enabled: boolean | null;
  adaptive_enabled: boolean | null;
  observe_only: boolean | null;
  admission: AdmissionConfig;
};

export type RuleSetRow = {
  id: string;
  name: string;
  rule_count: number;
  enabled_count: number;
  enabled: boolean;
  path: string;
};

export type RuleSetsOut = {
  pack: string;
  count: number;
  sets: RuleSetRow[];
};

export type RuleDoc = {
  summary: string;
  detects?: string | null;
  block_examples?: string[];
  pass_examples?: string[];
  notes?: string | null;
};

export type RuleRow = {
  id: string;
  name: string;
  severity: string;
  tags: string[];
  score: number;
  action: string;
  min_level: string;
  rule_set: string;
  file: string;
  enabled: boolean;
  doc?: RuleDoc | null;
};

export type RulesOut = {
  pack: string;
  count: number;
  enabled_count: number;
  rules: RuleRow[];
};
