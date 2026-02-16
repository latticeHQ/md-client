import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: {
      index: "src/index.ts",
      "ssh-agent": "src/ssh-agent.ts",
    },
    format: ["esm", "cjs"],
    dts: {
      compilerOptions: {
        skipLibCheck: true,
      },
    },
    sourcemap: true,
    clean: true,
    splitting: false,
    treeshake: true,
    external: ["net", "buffer"],
  },
]);
