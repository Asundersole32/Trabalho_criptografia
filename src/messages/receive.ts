import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize } from "node:path";

import { WebSocketServer, WebSocket } from "ws";

import { openEnvelope, type Envelope } from "./envelope.ts";
import { sendMessage } from "./send.ts";
import { random, genRSA, generateThumbprint } from "./cryptosuite.ts";

const PORT = Number(process.argv[2] ?? 8080);
const NAME =
  process.argv[3] ??
  process.env.PEER_NAME ??
  "peer-" + random(3).toString("hex");
const PUBLIC_DIR = join(process.cwd(), "src", "messages", "public");


const serverENC = genRSA();

type InboxMsg = {
  id: string;
  fromSigPubPem?: string;
  timestamp?: number;
  receivedAt: number;
  plaintext: string;
};
const inbox: InboxMsg[] = [];
const seenIds = new Set<string>();

// --- HTTP helpers ---
function setCORS(res: any) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Accept, X-Requested-With"
  );
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
}
function contentTypeFor(path: string) {
  const ext = extname(path).toLowerCase();
  switch (ext) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    case ".png":
      return "image/png";
    case ".ico":
      return "image/x-icon";
    default:
      return "application/octet-stream";
  }
}
function safeJoin(base: string, p: string) {
  const full = normalize(join(base, p));
  if (!full.startsWith(base)) throw new Error("Path traversal");
  return full;
}
async function readBody(req: any): Promise<string> {
  return await new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c: Buffer) => (data += c));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}
function ok(res: any, data: unknown = { ok: true }) {
  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(data));
}
function bad(res: any, e: unknown) {
  const msg = (e as any)?.message ?? String(e);
  res.statusCode = 400;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify({ ok: false, error: msg }));
}
function notFound(res: any) {
  res.statusCode = 404;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify({ error: "not found" }));
}

// --- HTTP server (kept for inter-peer comms + static UI) ---
const server = createServer(async (req, res) => {
  try {
    setCORS(res);

    if (req.method === "OPTIONS") {
      res.statusCode = 204;
      return res.end();
    }

    // Inter-peer HTTP APIs (unchanged behavior)
    if (req.method === "GET" && req.url === "/pubkeys") {
      const thumbprint = generateThumbprint(serverENC)
      return ok(res, {
        serverId: "demonstracao-cripto",
        name: NAME,
        encPubPem: serverENC.publicKeyPem,
        thumbprint,
      });
    }

    if (req.method === "GET" && req.url?.startsWith("/messages")) {
      const url = new URL(req.url, "http://x");
      const offset = Number(url.searchParams.get("offset") ?? "0");
      const slice = inbox.slice(offset);
      return ok(res, { messages: slice, next: offset + slice.length });
    }

    if (req.method === "POST" && req.url === "/message") {
      // Inter-peer inbound message via HTTP
      try {
        const body = await readBody(req);
        const env: Envelope = JSON.parse(body);

        const plaintext = openEnvelope(
          env,
          serverENC.privateKeyPem,
          serverENC.publicKeyPem
        );

        const maybeId =
          (env as any)?.id ??
          (env as any)?.hash ??
          `${Date.now()}-${random(4).toString("hex")}`;

        if (!seenIds.has(maybeId)) {
          seenIds.add(maybeId);
          const item: InboxMsg = {
            id: maybeId,
            fromSigPubPem: (env as any)?.senderSigPubPem,
            timestamp: (env as any)?.timestamp,
            receivedAt: Date.now(),
            plaintext,
          };
          inbox.push(item);
          // Push to any connected UI clients over WS
          wsBroadcast({ event: "message", data: item });
        }

        return ok(res, { ok: true, receipt: maybeId });
      } catch (e) {
        console.error(e);
        return bad(res, e);
      }
    }

    if (req.method === "POST" && req.url === "/send") {
      // Optional: keep HTTP proxy-send for non-WS clients
      try {
        const body = await readBody(req);
        const { recipientBaseUrl, plaintextUtf8 } = JSON.parse(body || "{}");
        if (!recipientBaseUrl || !plaintextUtf8)
          return bad(res, new Error("recipientBaseUrl and plaintextUtf8 required"));
        const result = await sendMessage({ recipientBaseUrl, plaintextUtf8 });
        return ok(res, { ok: true, result });
      } catch (e) {
        console.error(e);
        return bad(res, e);
      }
    }

    // Static UI
    if (req.method === "GET") {
      const urlPath = new URL(req.url ?? "/", "http://x").pathname;
      const filePath = urlPath === "/" ? "/index.html" : urlPath;
      let fullPath: string;
      try {
        fullPath = safeJoin(PUBLIC_DIR, filePath);
      } catch {
        return notFound(res);
      }
      try {
        const s = await stat(fullPath);
        if (s.isFile()) {
          const data = await readFile(fullPath);
          res.statusCode = 200;
          res.setHeader("Content-Type", contentTypeFor(fullPath));
          return res.end(data);
        }
      } catch {
        // fallthrough to 404
      }
    }

    return notFound(res);
  } catch (err) {
    console.error("Unhandled error:", err);
    return bad(res, err);
  }
});

// --- WebSocket server for local UI <-> backend ---
type WsRequest =
  | { id: string; action: "info" }
  | { id: string; action: "list"; since?: number }
  | { id: string; action: "send"; recipientBaseUrl: string; plaintextUtf8: string }
  | { id: string; action: "ping" };

type WsResponse =
  | { id: string; ok: true; data: any }
  | { id: string; ok: false; error: string };

const clients = new Set<WebSocket>();

const wss = new WebSocketServer({ noServer: true });

function wsSend(ws: WebSocket, obj: any) {
  try {
    ws.send(JSON.stringify(obj));
  } catch { }
}
function wsBroadcast(obj: any) {
  for (const c of clients) wsSend(c, obj);
}

wss.on("connection", (ws) => {
  clients.add(ws);

  // Optional initial hello
  const thumbprint = generateThumbprint(serverENC);
  wsSend(ws, {
    event: "hello",
    data: { name: NAME, serverId: "demonstracao-cripto", thumbprint },
  });

  ws.on("message", async (data) => {
    let msg: WsRequest | any;
    try {
      msg = JSON.parse(String(data));
    } catch {
      return wsSend(ws, { id: undefined, ok: false, error: "bad json" } as WsResponse);
    }

    const reply = (payload: WsResponse) => wsSend(ws, payload);

    try {
      if (msg.action === "info") {
        return reply({
          id: msg.id,
          ok: true,
          data: {
            name: NAME,
            serverId: "demonstracao-cripto",
            encPubPem: serverENC.publicKeyPem,
            thumbprint,
          },
        });
      }

      if (msg.action === "list") {
        const since = Number(msg.since ?? 0);
        const slice = inbox.slice(since);
        return reply({ id: msg.id, ok: true, data: { messages: slice, next: since + slice.length } });
      }

      if (msg.action === "send") {
        const { recipientBaseUrl, plaintextUtf8 } = msg;
        if (!recipientBaseUrl || !plaintextUtf8)
          return reply({ id: msg.id, ok: false, error: "recipientBaseUrl and plaintextUtf8 required" });
        const result = await sendMessage({ recipientBaseUrl, plaintextUtf8 });
        return reply({ id: msg.id, ok: true, data: { result } });
      }

      if (msg.action === "ping") {
        return reply({ id: msg.id, ok: true, data: "pong" });
      }

      return reply({ id: msg.id, ok: false, error: "unknown action" });
    } catch (e: any) {
      return reply({ id: msg.id, ok: false, error: e?.message ?? String(e) });
    }
  });

  ws.on("close", () => {
    clients.delete(ws);
  });
});

// Upgrade HTTP → WS for /ws
server.on("upgrade", (req, socket, head) => {
  try {
    const { pathname } = new URL(req.url ?? "/", "http://localhost");
    if (pathname !== "/ws") {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
  } catch {
    socket.destroy();
  }
});

server.listen(PORT, () => {
  console.log(`Name: ${NAME}`);
  console.log(`Recebendo dados em http://localhost:${PORT}`);
  console.log(`UI: http://localhost:${PORT}/`);
  console.log(`WS: ws://localhost:${PORT}/ws`);
});
