import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Operator-only lab overlay: additional pairing endpoint is loopback-only on PC2.
// Never enable the bridge outside the Tailscale-bound disposable lab.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/ws": {
        target: "ws://127.0.0.1:8080",
        ws: true
      },
      "/lab-session": "http://127.0.0.1:8766"
    }
  },
  test: {
    environment: "jsdom",
    globals: true
  }
});
