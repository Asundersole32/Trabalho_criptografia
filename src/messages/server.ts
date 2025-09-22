import { genEd25519, genX25519, b64 } from "./cryptosuite.ts";
import { openEnvelope, type Envelope } from "./envelope.ts";
import { createServer } from "node:http";

// === Generate a static X25519 keypair for this server instance ===
const serverKX = genX25519();

// We don't require the server to sign anything in this demo, but you could
// publish this if you wanted server-authenticated responses.
const serverSIG = genEd25519();

const server = createServer(async (req, res) => {
  // CORS & JSON default headers (handy for local tests)
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");

  if (req.method === "GET" && req.url === "/pubkeys") {
    res.end(
      JSON.stringify({
        serverId: "demo-server",
        kxPubPem: serverKX.publicKeyPem,
        sigPubPem: serverSIG.publicKeyPem,
        thumbprint: b64(new TextEncoder().encode(serverKX.publicKeyPem)).slice(
          0,
          16
        ),
      })
    );
    return;
  }

  if (req.method === "POST" && req.url === "/message") {
    try {
      const body = await new Promise<string>((resolve, reject) => {
        let data = "";
        req.on("data", (c) => (data += c));
        req.on("end", () => resolve(data));
        req.on("error", reject);
      });
      const env: Envelope = JSON.parse(body);

      const plaintext = openEnvelope(
        env,
        serverKX.privateKeyPem,
        serverKX.publicKeyPem
      );
      console.log("\n📥 Received message:", plaintext);

      res.statusCode = 200;
      res.end(JSON.stringify({ ok: true }));
    } catch (e: any) {
      res.statusCode = 400;
      console.error(e);
      res.end(JSON.stringify({ ok: false, error: e?.message ?? String(e) }));
    }
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not found" }));
});

const PORT = process.env.PORT ? Number(process.env.PORT) : 8080;
server.listen(PORT, () =>
  console.log(`▶️ demo server on http://localhost:${PORT}`)
);
