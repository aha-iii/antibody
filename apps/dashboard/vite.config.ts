import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

/** Expert Dashboard：5178；API 代理到 nerve-antibody-dashboard :8790 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // @nerve/ui 以源码形式随仓库提供（apps/dashboard/vendor/nerve-ui），
      // 走 Vite alias 直读 TS，无需预构建，也不依赖仓库外的同级目录。
      "@nerve/ui/style.css": fileURLToPath(
        new URL("./vendor/nerve-ui/src/styles/index.css", import.meta.url),
      ),
      "@nerve/ui": fileURLToPath(
        new URL("./vendor/nerve-ui/src/index.ts", import.meta.url),
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
