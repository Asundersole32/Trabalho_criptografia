import { createServer } from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { openEnvelope, type Envelope } from "./envelope.ts";

const PORT = process.argv[2] ?? "8080";

function genRSA() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}
const b64 = (u8: Uint8Array | Buffer) => Buffer.from(u8).toString("base64");

const serverENC = genRSA();

const server = createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");

  if (req.method === "GET" && req.url === "/pubkeys") {
    const thumbprint = b64(Buffer.from(serverENC.publicKeyPem)).slice(0, 16);
    res.end(
      JSON.stringify({
        serverId: "demonstracao-cripto",
        encPubPem: serverENC.publicKeyPem,
        thumbprint,
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
        serverENC.privateKeyPem,
        serverENC.publicKeyPem
      );

      console.log("\nMensagem recebida:", plaintext);

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

server.listen(PORT, () =>
  console.log(`Recebendo dados em http://localhost:${PORT}`)
);
