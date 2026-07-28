import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  // 构建产物输出到后端托管目录
 build: {
   outDir: "../web/dist",
   emptyOutDir: true,
   rollupOptions: {
     output: {
       manualChunks: {
         vendor: ["vue", "vue-router"],
         markdown: ["marked", "dompurify"],
       },
     },
   },
 },
 server: {
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true, ws: true },
    },
  },
});
