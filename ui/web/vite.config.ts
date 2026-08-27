import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The built assets are served by the Sentinel console (ui/server.py) from
// ui/web/dist, so `dist` is committed and a judge needs no npm to run it.
// In development, `npm run dev` proxies the API to the Python server.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8792",
        changeOrigin: true,
      },
    },
  },
});
