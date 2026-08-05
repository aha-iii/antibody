import { NerveLoginPage } from "@nerve/ui";
import { loginLocal } from "../auth";

type Props = {
  onSuccess: () => void;
};

export function LoginPage({ onSuccess }: Props) {
  return (
    <NerveLoginPage
      mark="N"
      productName="Nerve Native"
      productTagline="Expert 引擎 · 规则包与评测控制台"
      headline="规则包开发 · Bench 评测 · 指标观测"
      description="Baseline 规则维护、语义层 Shadow 验证与 Expert 引擎本地调试，支撑 WAF 能力迭代与质量门禁。"
      points={[
        "Baseline 规则包管理",
        "Bench 评测与指标对比",
        "本地 Expert 调试环境",
      ]}
      footer="© Nerve Native · Expert 引擎控制台"
      onLogin={async (username, password) => {
        await loginLocal(username, password);
        onSuccess();
      }}
    />
  );
}
