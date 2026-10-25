import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 5173 is one of the origins the backend's CORS allow-list accepts
// (BSA_DASHBOARD_ORIGINS), so keep it fixed instead of letting Vite pick another.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, strictPort: true },
  preview: { port: 5173, strictPort: true },
  test: {
    environment: "jsdom",
    setupFiles: ["./tests/setup.js"],
    globals: true,
  },
});
