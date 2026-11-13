import { useEffect, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { createRoot } from "react-dom/client";
import { NerveButton } from "../Button";
import { cx } from "../../utils/cx";

export type ShowModalContext = { close: () => void };
export type ShowModalRender = (ctx: ShowModalContext) => ReactNode;

export type NerveModalProps = {
  open: boolean;
  title: ReactNode;
  onClose: () => void;
  children?: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  xl?: boolean;
  maskClosable?: boolean;
};

/** nerve-dialog / ant-modal */
export function NerveModal({
  open,
  title,
  onClose,
  children,
  footer,
  wide,
  xl,
  maskClosable = true,
}: NerveModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return createPortal(
    <div
      className="nerve-dialog-mask ant-modal-mask"
      onClick={(e) => {
        if (maskClosable && e.target === e.currentTarget) onClose();
      }}
    >
      <div className="nerve-dialog-wrap ant-modal-wrap">
        <div
          className={cx("nerve-dialog", "ant-modal", wide && "ant-modal-wide", xl && "ant-modal-xl")}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="nerve-dialog-header ant-modal-header">
            <span>{title}</span>
            <button type="button" className="nerve-dialog-close ant-modal-close" onClick={onClose}>
              ×
            </button>
          </div>
          <div className="nerve-dialog-body ant-modal-body">{children}</div>
          {footer != null ? (
            <div className="nerve-dialog-footer ant-modal-footer">{footer}</div>
          ) : null}
        </div>
      </div>
    </div>,
    document.body,
  );
}

/**
 * 命令式挂载弹窗（对齐 legacy Console showModal）。
 * render 内自行使用 NerveModal，close 时卸载并 resolve。
 */
export function showModal(render: ShowModalRender): Promise<void> {
  return new Promise((resolve) => {
    const host = document.createElement("div");
    document.body.appendChild(host);
    const root = createRoot(host);
    const close = () => {
      root.unmount();
      host.remove();
      resolve();
    };
    root.render(render({ close }));
  });
}

export type NerveConfirmOptions = {
  title: string;
  message: ReactNode;
  okText?: string;
  cancelText?: string;
  danger?: boolean;
};

/** 命令式确认，对齐原 Console showConfirm */
export function nerveConfirm(opts: NerveConfirmOptions): Promise<boolean> {
  return new Promise((resolve) => {
    const host = document.createElement("div");
    document.body.appendChild(host);
    const root = createRoot(host);

    const finish = (ok: boolean) => {
      root.unmount();
      host.remove();
      resolve(ok);
    };

    root.render(
      <NerveModal
        open
        title={opts.title}
        onClose={() => finish(false)}
        footer={
          <>
            <NerveButton onClick={() => finish(false)}>{opts.cancelText ?? "取消"}</NerveButton>
            <NerveButton
              variant={opts.danger ? "danger" : "primary"}
              onClick={() => finish(true)}
            >
              {opts.okText ?? "确定"}
            </NerveButton>
          </>
        }
      >
        <p className="confirm-message">{opts.message}</p>
      </NerveModal>,
    );
  });
}

export type NerveResultOptions = {
  type: "success" | "error" | "info";
  title: string;
  message?: ReactNode;
  okText?: string;
};

/** 命令式结果弹窗，对齐原 showResult */
export function nerveResult(opts: NerveResultOptions): Promise<void> {
  return new Promise((resolve) => {
    const host = document.createElement("div");
    document.body.appendChild(host);
    const root = createRoot(host);
    const finish = () => {
      root.unmount();
      host.remove();
      resolve();
    };
    root.render(
      <NerveModal
        open
        title={opts.message != null ? opts.title : "提示"}
        onClose={finish}
        footer={
          <NerveButton variant="primary" onClick={finish}>
            {opts.okText ?? "知道了"}
          </NerveButton>
        }
      >
        <div className="nerve-result-body">
          <p className="confirm-message">
            {opts.message != null ? opts.message : opts.title}
          </p>
        </div>
      </NerveModal>,
    );
  });
}
