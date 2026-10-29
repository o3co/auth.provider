import { secretBytes } from "@mod/keys";
import { z } from "zod";

/** A key id: it heads every sealed value, so it holds no dot. */
export const keyId = /^[A-Za-z0-9_-]{1,32}$/;

/** Each algorithm a key may seal with, and the sizes of its key, IV and tag in bytes. */
export const algorithms = {
	"aes-256-gcm": { keyBytes: 32, ivBytes: 12, tagBytes: 16 },
} as const;
export type Algorithm = keyof typeof algorithms;

const entry = z.strictObject({
	id: z.string().regex(keyId).describe("The key's id, which heads every value it seals."),
	algorithm: z
		.enum(Object.keys(algorithms) as [Algorithm])
		.prefault("aes-256-gcm")
		.describe("What the key seals and opens with: aes-256-gcm, the default and only one."),
	key: z
		.string()
		.describe(
			"The key's bytes, base64, as many as its algorithm takes, of at least 8 byte values.",
		),
});
/** A key's bytes are held to its algorithm's size, by `keys`' rule for a secret's bytes. */
const sized = <T extends typeof entry>(shape: T) =>
	shape.superRefine((k, ctx) => {
		const bytes = { exactly: algorithms[k.algorithm].keyBytes };
		for (const issue of secretBytes(bytes).safeParse(k.key).error?.issues ?? []) {
			ctx.addIssue({ code: "custom", message: issue.message, path: ["key"] });
		}
	});
const key = sized(entry);

/** The key ring: one key seals, and every key of it opens. */
export const section = z
	.strictObject({
		current: key.describe("The key that seals; any key of the ring opens."),
		next: sized(
			entry.extend({
				id: entry.shape.id.describe(
					"The key's id: it opens values but seals none until it is made current.",
				),
			}),
		)
			.optional()
			.describe("Opens but never seals, so every host opens with it before it seals."),
		previous: z.array(key).prefault([]).describe("Keys that only open what they sealed."),
	})
	.refine((s) => {
		const ids = [s.current, ...(s.next ? [s.next] : []), ...s.previous].map((k) => k.id);
		return new Set(ids).size === ids.length;
	}, "ids must differ");
