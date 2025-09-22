import * as crypto from "node:crypto";
const key = Buffer.from(
  "ow/uZM8QOpzcCQjzni4c1+VWvkhXM2YQN1BsK3e0teQ=",
  "base64"
);
const iv = Buffer.from("vWv6yeC6nQEfmSdZMAiy+Q==", "base64");
const ct = Buffer.from("vWv6yeC6nQEfmSdZMAiy+Q==", "base64"); // <- your ct (currently same as iv)

const dec = crypto.createDecipheriv("aes-256-cbc", key, iv);
dec.setAutoPadding(false);
const padded = Buffer.concat([dec.update(ct), dec.final()]);
console.log("node lastByte =", padded[padded.length - 1]);
