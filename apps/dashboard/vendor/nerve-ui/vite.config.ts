import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import dts from "vite-plugin-dts";
import { resolve } from "node:path";

export default defineConfig({
  plugins: [
    react(),
    dts({
      include: ["src"],
      outDir: "dist",
      rollupTypes: true,
      tsconfigPath: "./tsconfig.build.json",
    }),
  ],
  build: {
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      name: "NerveUI",
      formats: ["es", "cjs"],
      fileName: (format) => (format === "es" ? "nerve-ui.js" : "nerve-ui.cjs"),
    },
    rollupOptions: {
      external: ["react", "react-dom", "react/jsx-runtime"],
      output: {
        assetFileNames: "nerve-ui.[ext]",
        globals: {
          react: "React",
          "react-dom": "ReactDOM",
        },
      },
    },
    cssCodeSplit: false,
    sourcemap: true,
  },
});
