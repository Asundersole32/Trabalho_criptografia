import { genEd25519 } from "./cryptosuite.ts";
import { createEnvelope } from "./envelope.ts";

const RECIPIENT = process.argv[2] ?? "http://localhost:8080";
const MESSAGE = process.argv.slice(3).join(" ") || "hello from the SENent";

async function main() {
  // Pega a chave publica do destinatario (RSA)
  const info = await fetch(`${RECIPIENT}/pubkeys`).then((r) => r.json());
  const recipientEncPubPem = info.encPubPem as string;

  // Gerar um par de chaves assimetricas para assinatura digital (Ed25519)
  const SENentSIG = genEd25519();

  const env = createEnvelope({
    plaintextUtf8: MESSAGE,
    senderSigPrivPem: SENentSIG.privateKeyPem,
    senderSigPubPem: SENentSIG.publicKeyPem,
    recipientEncPubPem,
  });

  // Envia a mensagem envelopada
  const resp = await fetch(`${RECIPIENT}/message`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(env),
  }).then((r) => r.json());

  console.log("\nEnviando mensagem.", resp);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
