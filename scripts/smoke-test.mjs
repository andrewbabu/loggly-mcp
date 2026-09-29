import { spawn } from "node:child_process";
import { resolve } from "node:path";

const entry = resolve("src/index.js");
const nodeBin = process.execPath;

const child = spawn(nodeBin, [entry], {
  env: {
    ...process.env,
    LOGGLY_SMOKE_TEST: "1"
  },
  stdio: ["ignore", "pipe", "pipe"]
});

let stdout = "";
let stderr = "";
const timeoutMs = 5000;
const timeout = setTimeout(() => {
  child.kill("SIGKILL");
  console.error(`Smoke test timed out after ${timeoutMs}ms.`);
  if (stdout) {
    console.error("stdout:\n" + stdout.trim());
  }
  if (stderr) {
    console.error("stderr:\n" + stderr.trim());
  }
  process.exit(1);
}, timeoutMs);

child.stdout.on("data", (chunk) => {
  stdout += chunk.toString();
});

child.stderr.on("data", (chunk) => {
  stderr += chunk.toString();
});

child.on("exit", (code) => {
  clearTimeout(timeout);
  if (code === 0) {
    if (stdout.trim()) {
      console.log(stdout.trim());
    }
    process.exit(0);
  }

  console.error(`Smoke test failed with exit code ${code}.`);
  if (stdout) {
    console.error("stdout:\n" + stdout.trim());
  }
  if (stderr) {
    console.error("stderr:\n" + stderr.trim());
  }
  process.exit(code ?? 1);
});
