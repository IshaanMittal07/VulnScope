import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    // Docker Desktop on WSL2 bind mounts don't emit inotify events reliably.
    watch: { usePolling: true },
  },
});
