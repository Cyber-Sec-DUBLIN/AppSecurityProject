import { defineConfig } from 'astro/config';

// Static frontend; all data is fetched client-side from the Rust API on :8080.
export default defineConfig({
  server: { port: 4321, host: true },
});
