import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type NerveToastFn = (msg: string, ok?: boolean) => void;

const ToastCtx = createContext<NerveToastFn>(() => undefined);

let toastDispatch: NerveToastFn = () => undefined;

/** 命令式 toast，需在 ToastProvider 挂载后使用 */
export function nerveToast(msg: string, ok = true) {
  toastDispatch(msg, ok);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<{ id: number; msg: string; ok: boolean }[]>([]);

  const toast = useCallback<NerveToastFn>((msg, ok = true) => {
    const id = Date.now() + Math.random();
    setItems((prev) => [...prev, { id, msg, ok }]);
    window.setTimeout(() => {
      setItems((prev) => prev.filter((item) => item.id !== id));
    }, 3000);
  }, []);

  useEffect(() => {
    toastDispatch = toast;
    return () => {
      toastDispatch = () => undefined;
    };
  }, [toast]);

  const value = useMemo(() => toast, [toast]);

  return (
    <ToastCtx.Provider value={value}>
      {children}
      <div id="toast-root">
        {items.map((item) => (
          <div key={item.id} className={`toast show toast-${item.ok ? "ok" : "err"}`}>
            {item.msg}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast(): NerveToastFn {
  return useContext(ToastCtx);
}
