import { createRoot } from "react-dom/client";
import { ToastProvider } from "@nerve/ui";
import { App } from "./App";
import "@nerve/ui/style.css";
import "./app-local.css";

createRoot(document.getElementById("root")!).render(
  <ToastProvider>
    <App />
  </ToastProvider>,
);
