import { genEd25519 } from "./cryptosuite.ts";
import { createEnvelope } from "./envelope.ts";

export type RecipientInfo = {
  serverId?: string;
  name?: string;
  encPubPem: string;
  thumbprint?: string;
};

export async function fetchRecipientInfo(
  baseUrl: string
): Promise<RecipientInfo> {
  const url = baseUrl.replace(/\/+$/, "") + "/pubkeys";
  const info = await fetch(url).then((r) => {
    if (!r.ok) throw new Error(`Failed to fetch pubkeys from ${url}`);
    return r.json();
  });
  if (!info?.encPubPem) throw new Error("Missing encPubPem in recipient info");
  return info as RecipientInfo;
}

export type SendOptions = {
  recipientBaseUrl: string;
  plaintextUtf8: string;
  senderSigPrivPem?: string;
  senderSigPubPem?: string;
};

export async function sendMessage(opts: SendOptions) {
  const { recipientBaseUrl, plaintextUtf8 } = opts;
  if (!recipientBaseUrl || !plaintextUtf8)
    throw new Error("recipientBaseUrl and plaintextUtf8 are required");

  // 1) Recipient RSA public key
  const { encPubPem } = await fetchRecipientInfo(recipientBaseUrl);

  // 2) Sender Ed25519 (ephemeral by default)
  const sender =
    opts.senderSigPrivPem && opts.senderSigPubPem
      ? { privateKeyPem: opts.senderSigPrivPem, publicKeyPem: opts.senderSigPubPem }
      : genEd25519();

  // 3) Create envelope
  const env = createEnvelope({
    plaintextUtf8,
    senderSigPrivPem: sender.privateKeyPem,
    senderSigPubPem: sender.publicKeyPem,
    recipientEncPubPem: encPubPem,
  });

  // 4) POST /message
  const url = recipientBaseUrl.replace(/\/+$/, "") + "/message";
  const resp = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(env),
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Send failed (${resp.status}): ${text || resp.statusText}`);
  }
  return resp.json();
}
