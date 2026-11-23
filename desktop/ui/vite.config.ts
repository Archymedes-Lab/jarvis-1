import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  // base "./": the same files load from the app (tauri://localhost/) and from the daemon (/ui/).
  base: "./",
  plugins: [svelte(), tailwindcss()],
  clearScreen: false,
  server: { port: 5199, strictPort: true, host: "127.0.0.1" },
  build: { target: "es2022", outDir: "dist", emptyOutDir: true, assetsInlineLimit: 0, sourcemap: false },
});
