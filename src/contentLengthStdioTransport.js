import process from "node:process";

/**
 * Content-Length framed stdio transport for MCP JSON-RPC.
 * Accepts CRLF or LF-delimited Content-Length frames,
 * JSON text sequences, and newline-delimited JSON.
 */
export class ContentLengthStdioServerTransport {
  constructor(stdin = process.stdin, stdout = process.stdout) {
    this._stdin = stdin;
    this._stdout = stdout;
    this._buffer = Buffer.alloc(0);
    this._started = false;
    this._outboundMode = "content-length";

    this.onmessage = undefined;
    this.onerror = undefined;
    this.onclose = undefined;

    this._ondata = (chunk) => {
      this._buffer = Buffer.concat([this._buffer, chunk]);
      this._consumeFrames();
    };

    this._onerror = (error) => {
      this.onerror?.(error);
    };
  }

  async start() {
    if (this._started) {
      throw new Error(
        "ContentLengthStdioServerTransport already started. connect() starts transport automatically.",
      );
    }

    this._started = true;
    this._stdin.on("data", this._ondata);
    this._stdin.on("error", this._onerror);
  }

  _consumeFrames() {
    while (true) {
      if (this._consumeContentLengthFrame()) {
        continue;
      }
      if (this._consumeJsonSequenceFrame()) {
        continue;
      }
      if (this._consumeJsonLineFrame()) {
        continue;
      }
      return;
    }
  }

  _consumeContentLengthFrame() {
    const headerInfo = this._findContentLengthHeader();
    if (!headerInfo) {
      return false;
    }

    const frameEnd =
      headerInfo.headerEnd +
      headerInfo.delimiterLength +
      headerInfo.contentLength;
    if (this._buffer.length < frameEnd) {
      return false;
    }

    const body = this._buffer
      .subarray(headerInfo.headerEnd + headerInfo.delimiterLength, frameEnd)
      .toString("utf8");
    this._buffer = this._buffer.subarray(frameEnd);

    try {
      const message = JSON.parse(body);
      this._outboundMode = "content-length";
      this.onmessage?.(message);
    } catch (error) {
      this.onerror?.(
        new Error(`Invalid JSON frame body: ${error?.message || error}`),
      );
    }

    return true;
  }

  _consumeJsonLineFrame() {
    const startsWithContentLength = this._buffer
      .subarray(0, 32)
      .toString("utf8")
      .toLowerCase()
      .startsWith("content-length:");
    if (startsWithContentLength) {
      return false;
    }

    const newlineIndex = this._buffer.indexOf("\n");
    if (newlineIndex === -1) {
      return false;
    }

    let line = this._buffer.subarray(0, newlineIndex).toString("utf8");
    this._buffer = this._buffer.subarray(newlineIndex + 1);
    line = line.trim();
    if (!line) {
      return true;
    }

    try {
      const message = JSON.parse(line);
      this._outboundMode = "json-line";
      this.onmessage?.(message);
    } catch (error) {
      this.onerror?.(
        new Error(`Invalid JSON line body: ${error?.message || error}`),
      );
    }

    return true;
  }

  _consumeJsonSequenceFrame() {
    const RS = 0x1e;
    while (this._buffer.length > 0 && this._isAsciiWhitespace(this._buffer[0])) {
      this._buffer = this._buffer.subarray(1);
    }
    if (this._buffer.length === 0 || this._buffer[0] !== RS) {
      return false;
    }

    const newlineIndex = this._buffer.indexOf("\n", 1);
    if (newlineIndex === -1) {
      return false;
    }

    const body = this._buffer.subarray(1, newlineIndex).toString("utf8").trim();
    this._buffer = this._buffer.subarray(newlineIndex + 1);
    if (!body) {
      return true;
    }

    try {
      const message = JSON.parse(body);
      this._outboundMode = "json-seq";
      this.onmessage?.(message);
    } catch (error) {
      this.onerror?.(
        new Error(`Invalid JSON sequence body: ${error?.message || error}`),
      );
    }

    return true;
  }

  _isAsciiWhitespace(byte) {
    return byte === 0x20 || byte === 0x09 || byte === 0x0d || byte === 0x0a;
  }

  _findContentLengthHeader() {
    const candidates = [];
    const headerEndCrLf = this._buffer.indexOf("\r\n\r\n");
    if (headerEndCrLf !== -1) {
      candidates.push({ headerEnd: headerEndCrLf, delimiterLength: 4 });
    }
    const headerEndLf = this._buffer.indexOf("\n\n");
    if (headerEndLf !== -1) {
      candidates.push({ headerEnd: headerEndLf, delimiterLength: 2 });
    }

    candidates.sort((a, b) => a.headerEnd - b.headerEnd);

    for (const candidate of candidates) {
      const headerText = this._buffer
        .subarray(0, candidate.headerEnd)
        .toString("utf8");
      const contentLength = this._parseContentLength(headerText);
      if (contentLength != null) {
        return { ...candidate, contentLength };
      }
    }

    return null;
  }

  _parseContentLength(headerText) {
    const lines = headerText.split(/\r?\n/);

    for (const line of lines) {
      const idx = line.indexOf(":");
      if (idx === -1) {
        continue;
      }

      const name = line.slice(0, idx).trim().toLowerCase();
      const value = line.slice(idx + 1).trim();

      if (name === "content-length") {
        const parsed = Number.parseInt(value, 10);
        if (Number.isInteger(parsed) && parsed >= 0) {
          return parsed;
        }
        return null;
      }
    }

    return null;
  }

  async close() {
    this._stdin.off("data", this._ondata);
    this._stdin.off("error", this._onerror);

    if (this._stdin.listenerCount("data") === 0) {
      this._stdin.pause();
    }

    this._buffer = Buffer.alloc(0);
    this.onclose?.();
  }

  send(message) {
    return new Promise((resolve) => {
      const json = JSON.stringify(message);
      const payload =
        this._outboundMode === "json-line"
          ? `${json}\n`
          : this._outboundMode === "json-seq"
            ? `\u001e${json}\n`
            : `Content-Length: ${Buffer.byteLength(json, "utf8")}\r\n\r\n${json}`;

      if (this._stdout.write(payload)) {
        resolve();
      } else {
        this._stdout.once("drain", resolve);
      }
    });
  }
}
