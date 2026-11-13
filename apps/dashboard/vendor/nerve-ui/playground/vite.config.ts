import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

export default defineConfig({
  root: resolve(__dirname),
  plugins: [react()],
  resolve: {
    alias: {
      "@nerve/ui": resolve(__dirname, "../src/index.ts"),
    },
  },
  server: {
    port: 5199,
    strictPort: true,
    host: "0.0.0.0",
    allowedHosts: true,
    watch: {
      usePolling: process.env.VITE_USE_POLLING === "1",
      ignored: ["**/node_modules/**", "**/.git/**"],
    },
  },
});
