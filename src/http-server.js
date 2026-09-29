import { createServer as createHttpServer } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer as createMcpServer, log, SERVER_VERSION } from "./server.js";

const PORT = Number.parseInt(process.env.MCP_HTTP_PORT || "8787", 10);
const BEARER_TOKEN = process.env.MCP_BEARER_TOKEN;
const MCP_PATH = "/mcp";

if (!BEARER_TOKEN || !BEARER_TOKEN.trim()) {
  console.error(
    "[loggly-mcp-http] MCP_BEARER_TOKEN is not set. Refusing to start an unauthenticated remote server."
  );
  process.exit(1);
}

function isAuthorized(req) {
  const header = req.headers["authorization"];
  if (!header || !header.startsWith("Bearer ")) {
    return false;
  }

  const provided = header.slice("Bearer ".length).trim();
  const expected = BEARER_TOKEN;

  const providedBuf = Buffer.from(provided);
  const expectedBuf = Buffer.from(expected);

  if (providedBuf.length !== expectedBuf.length) {
    return false;
  }

  return timingSafeEqual(providedBuf, expectedBuf);
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body)
  });
  res.end(body);
}

const httpServer = createHttpServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (url.pathname === "/healthz") {
    sendJson(res, 200, { ok: true, name: "loggly-api-mcp", version: SERVER_VERSION });
    return;
  }

  if (url.pathname !== MCP_PATH) {
    sendJson(res, 404, { error: "Not found." });
    return;
  }

  if (!isAuthorized(req)) {
    log("warn", "Rejected unauthenticated MCP request.", {
      method: req.method,
      path: url.pathname
    });
    res.setHeader("WWW-Authenticate", 'Bearer realm="loggly-mcp"');
    sendJson(res, 401, { error: "Unauthorized." });
    return;
  }

  if (req.method !== "POST") {
    sendJson(res, 405, { error: "Method not allowed. This server only supports stateless POST." });
    return;
  }

  // Stateless mode: a fresh MCP server + transport per request, torn down
  // once the response closes. No session state, no SSE stream to manage.
  const { server: mcpServer } = createMcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });

  res.on("close", () => {
    transport.close();
    mcpServer.close();
  });

  try {
    await mcpServer.connect(transport);
    await transport.handleRequest(req, res);
  } catch (error) {
    log("error", "Failed to handle MCP request.", {
      message: error instanceof Error ? error.message : String(error)
    });
    if (!res.headersSent) {
      sendJson(res, 500, { error: "Internal server error." });
    }
  }
});

httpServer.listen(PORT, () => {
  log("info", "Starting Loggly MCP HTTP server.", {
    version: SERVER_VERSION,
    port: PORT,
    path: MCP_PATH
  });
});
