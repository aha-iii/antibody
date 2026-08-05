export type PageId =
  | "overview"
  | "packs"
  | "level"
  | "semantic"
  | "algorithm"
  | "admission"
  | "samples"
  | "bench"
  | "metrics"
  | "shadow"
  | "engine";

export type NavItem = {
  id: PageId;
  group: string;
  icon: string;
  label: string;
};

export const NAV: NavItem[] = [
  { id: "overview", group: "配置", icon: "◈", label: "总览" },
  { id: "packs", group: "配置", icon: "▣", label: "规则集" },
  { id: "level", group: "配置", icon: "◐", label: "防护粒度" },
  { id: "semantic", group: "配置", icon: "◎", label: "语义" },
  { id: "algorithm", group: "配置", icon: "⬡", label: "算法" },
  { id: "admission", group: "配置", icon: "⛨", label: "准入防护" },
  { id: "samples", group: "实验室", icon: "▤", label: "案例库" },
  { id: "bench", group: "实验室", icon: "◎", label: "拦截率测试" },
  { id: "metrics", group: "运维", icon: "◉", label: "可观测" },
  { id: "shadow", group: "运维", icon: "◌", label: "误报 / Shadow" },
  { id: "engine", group: "运维", icon: "◇", label: "引擎状态" },
];

export const PAGE_META: Record<PageId, { title: string; subtitle: string }> = {
  overview: { title: "总览", subtitle: "" },
  packs: { title: "规则集", subtitle: "rules/ 下各文件夹" },
  level: { title: "防护粒度", subtitle: "" },
  semantic: { title: "语义", subtitle: "pack 策略 + 试打 overlay" },
  algorithm: { title: "算法", subtitle: "adaptive / model / inspect" },
  admission: { title: "准入防护", subtitle: "" },
  samples: { title: "案例库", subtitle: "" },
  bench: { title: "拦截率测试", subtitle: "" },
  metrics: { title: "可观测", subtitle: "runtime metrics" },
  shadow: { title: "误报 / Shadow", subtitle: "标注与 allow 草稿" },
  engine: { title: "引擎状态", subtitle: "" },
};

export const DASHBOARD_BUILD = "0.3.1";
