import { genEd25519 } from "./cryptosuite.ts";
import { createEnvelope } from "./envelope.ts";

const SERVER = process.argv[2] ?? "http://localhost:8080";
const MESSAGE = process.argv.slice(3).join(" ") || "hello from the client";

async function main() {
  // 1) Fetch recipient's (server) static X25519 public key
  const info = await fetch(`${SERVER}/pubkeys`).then((r) => r.json());
  const recipientKxPubPem = info.kxPubPem as string;

  // 2) Generate a signing keypair for the client (Ed25519)
  const clientSIG = genEd25519();

  // 3) Build an envelope (ephemeral X25519 inside)
  const env = createEnvelope({
    plaintextUtf8: MESSAGE,
    senderSigPrivPem: clientSIG.privateKeyPem,
    senderSigPubPem: clientSIG.publicKeyPem,
    recipientKxPubPem,
  });

  // 4) POST the envelope to the server
  const resp = await fetch(`${SERVER}/message`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(env),
  }).then((r) => r.json());

  console.log("\n📤 Sent envelope. Server said:", resp);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
