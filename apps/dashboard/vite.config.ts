import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

/** Expert Dashboard：5178；API 代理到 nerve-antibody-dashboard :8790 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@nerve/ui/style.css": fileURLToPath(
        new URL("../../../../Nerve-ui/src/styles/index.css", import.meta.url),
      ),
      "@nerve/ui": fileURLToPath(
        new URL("../../../../Nerve-ui/src/index.ts", import.meta.url),
      ),
    },
  },
  server: {
    port: 5178,
    strictPort: true,
    host: "0.0.0.0",
    // WSL 监视 /mnt/d（Windows 盘）易 EMFILE；轮询更稳
    watch: {
      usePolling: true,
      interval: 800,
    },
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8790",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
