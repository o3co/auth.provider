import { createCipheriv, createDecipheriv } from "node:crypto";
import { defineModule, Unavailable } from "@mod/kernel";
import { type Opened, type Resealed, resealers, resealing, seal } from "./contract.ts";
import { type Algorithm, algorithms, keyId, section } from "./section.ts";

/** id.iv.body.tag, each part base64url; the IV's and the tag's sizes are the key's algorithm's. */
const sealedShape = new RegExp(
	`^(${keyId.source.slice(1, -1)})\\.([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]*)\\.([A-Za-z0-9_-]+)$`,
);
/** Sizes some algorithm writes, checked before the key is looked up, as a fixed shape was. */
const written = Object.values(algorithms);
const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
/** The bytes of a part written in its one form; a decoder drops a last character's spare bits. */
const bytesOf = (part: string) => {
	const bytes = Buffer.from(part, "base64url");
	return base64url(bytes) === part ? bytes : undefined;
};
/** What the tag covers beside the body: the key's id and the context, so neither can be swapped. */
const bound = (id: string, context: string) => Buffer.from(`${id}\n${context}`);

export default defineModule(
	{ name: "seal", section, replicaSafe: true, takes: [resealers] },
	(m) => [
		m.provide(seal).by((c) => {
			const { current, next, previous } = c.section;
			const opening = [current, ...(next ? [next] : []), ...previous];
			const ring = new Map(
				opening.map((k) => [k.id, { bytes: Buffer.from(k.key, "base64"), algorithm: k.algorithm }]),
			);
			const currentId = current.id;
			// Only a past key's values are stale: next is newer than current, as hosts move it up in turn.
			const pastIds = new Set(previous.map((k) => k.id));
			const sealing = ring.get(currentId) as { bytes: Buffer; algorithm: Algorithm };
			const sizes = algorithms[sealing.algorithm];
			return Object.freeze({
				seal: (plain: string, context: string) => {
					const iv = c.random.bytes(sizes.ivBytes);
					const cipher = createCipheriv(sealing.algorithm, sealing.bytes, iv, {
						authTagLength: sizes.tagBytes,
					});
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
					const fits = (a: (typeof written)[number]) =>
						iv.length === a.ivBytes && tag.length === a.tagBytes;
					if (!written.some(fits)) return { kind: "refused" };
					const key = ring.get(id);
					if (!key) throw new Unavailable("seal");
					if (!fits(algorithms[key.algorithm])) return { kind: "refused" };
					try {
						const decipher = createDecipheriv(key.algorithm, key.bytes, iv, {
							authTagLength: algorithms[key.algorithm].tagBytes,
						});
						decipher.setAAD(bound(id, context));
						decipher.setAuthTag(tag);
						const plain = Buffer.concat([decipher.update(body), decipher.final()]);
						const opened = { kind: "opened" as const, plain: plain.toString("utf8") };
						return pastIds.has(id) ? { ...opened, stale: true } : opened;
					} catch {
						return { kind: "refused" };
					}
				},
			});
		}),
		m.provide(resealing).by(async (c) => {
			const holders = [...(await c.collect(resealers))].sort((a, b) => (a.name < b.name ? -1 : 1));
			return {
				reseal: async () => {
					const told: Resealed[] = [];
					for (const holder of holders) {
						try {
							const { resealed, left } = await holder.reseal();
							told.push({ name: holder.name, resealed, left });
						} catch (error) {
							c.log.warn("seal.reseal_failed", {
								holder: holder.name,
								kind: error instanceof Error ? error.name : typeof error,
							});
							told.push({ name: holder.name, failed: true });
						}
					}
					return told;
				},
			};
		}),
	],
);
