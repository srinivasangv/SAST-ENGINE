import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard runs on :5173 and the Python API on :8000.
// The proxy means every component can just call fetch("/api/...") with no
// CORS juggling and no hard-coded hostname to change before a demo.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: true } },
  },
});
