#!/usr/bin/env node
import { ContentLengthStdioServerTransport } from "./contentLengthStdioTransport.js";
import { createServer, log, SERVER_VERSION, ACCOUNTS, DEFAULT_ACCOUNT_NAME } from "./server.js";

const SMOKE_TEST = process.env.LOGGLY_SMOKE_TEST === "1";
if (SMOKE_TEST) {
  console.log("Loggly MCP smoke test OK.");
  process.exit(0);
}

const { server } = createServer();
const transport = new ContentLengthStdioServerTransport();
log("info", "Starting Loggly MCP server.", {
  version: SERVER_VERSION,
  accounts: [...ACCOUNTS.keys()],
  default_account: DEFAULT_ACCOUNT_NAME
});
await server.connect(transport);
