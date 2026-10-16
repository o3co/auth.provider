import { createCipheriv, createDecipheriv } from "node:crypto";
import { defineModule, Unavailable } from "@mod/kernel";
import { type Opened, seal } from "./contract.ts";
import { keyId, section } from "./section.ts";

const algorithm = "aes-256-gcm";
const tagLength = 16;
/** id.iv.body.tag: a 12-byte IV and a 16-byte tag, each as base64url. */
const sealedShape = new RegExp(
	`^(${keyId.source.slice(1, -1)})\\.([A-Za-z0-9_-]{16})\\.([A-Za-z0-9_-]*)\\.([A-Za-z0-9_-]{22})$`,
);
const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
/** The bytes of a part written in its one form; a decoder drops a last character's spare bits. */
const bytesOf = (part: string) => {
	const bytes = Buffer.from(part, "base64url");
	return base64url(bytes) === part ? bytes : undefined;
};
/** What the tag covers beside the body: the key's id and the context, so neither can be swapped. */
const bound = (id: string, context: string) => Buffer.from(`${id}\n${context}`);

export default defineModule({ name: "seal", section, replicaSafe: true }, (m) => [
	m.provide(seal).by((c) => {
		const ring = new Map(c.section.keys.map((k) => [k.id, Buffer.from(k.key, "base64")]));
		// The section takes at least one key.
		const currentId = (c.section.keys[0] as { id: string }).id;
		const currentKey = ring.get(currentId) as Buffer;
		return Object.freeze({
			seal: (plain: string, context: string) => {
				const iv = c.random.bytes(12);
				const cipher = createCipheriv(algorithm, currentKey, iv, { authTagLength: tagLength });
				cipher.setAAD(bound(currentId, context));
				const body = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
				return `${currentId}.${base64url(iv)}.${base64url(body)}.${base64url(cipher.getAuthTag())}`;
			},
			open: (sealed: string, context: string): Opened => {
				const parts = sealedShape.exec(sealed);
				if (!parts) return { kind: "refused" };
				const [, id = "", ...encoded] = parts;
				const [iv, body, tag] = encoded.map(bytesOf);
				if (!iv || !body || !tag) return { kind: "refused" };
				const key = ring.get(id);
				if (!key) throw new Unavailable("seal");
				try {
					const decipher = createDecipheriv(algorithm, key, iv, {
						authTagLength: tagLength,
					});
					decipher.setAAD(bound(id, context));
					decipher.setAuthTag(tag);
					const plain = Buffer.concat([decipher.update(body), decipher.final()]);
					return { kind: "opened", plain: plain.toString("utf8") };
				} catch {
					return { kind: "refused" };
				}
			},
		});
	}),
]);
