import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import dotenv from "dotenv";

import { UserConfigExport } from "vite";

const config: UserConfigExport = defineConfig({
  logLevel: "error",
  plugins: [react()],
  define: {
    "import.meta.env": Object.fromEntries(
      Object.entries(process.env).map(([key, value]) => [`VITE_${key}`, value])
    ),
  },
  resolve: {
    alias: {
      "@components": "/src/components",
      "@controllers": "/src/controllers",
      "@pages": "/src/pages",
      "@routes": "/src/routes",
      "@styles": "/src/styles",
      "@stores": "/src/stores",
    },
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:6901",
        changeOrigin: true,
        ws: true,
      },
    },
    port: 6900,
  }
});

export default config;