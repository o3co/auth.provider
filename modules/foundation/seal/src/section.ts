import { secretBytes } from "@mod/keys";
import { z } from "zod";

/** A key id: it heads every sealed value, so it holds no dot. */
export const keyId = /^[A-Za-z0-9_-]{1,32}$/;

const key = z.strictObject({
	id: z.string().regex(keyId).describe("The key's id, which heads every value it seals."),
	key: secretBytes({ exactly: 32 }).describe("32 bytes, base64, of at least 8 byte values."),
});

/** The key ring: one key seals, and every key of it opens. */
export const section = z
	.strictObject({
		current: key.describe("The key that seals; any key of the ring opens."),
		next: key
			.extend({
				id: z
					.string()
					.regex(keyId)
					.describe("The key's id: it opens values but seals none until it is made current."),
			})
			.optional()
			.describe("Opens but never seals, so every host opens with it before it seals."),
		previous: z.array(key).prefault([]).describe("Keys that only open what they sealed."),
	})
	.refine((s) => {
		const ids = [s.current, ...(s.next ? [s.next] : []), ...s.previous].map((k) => k.id);
		return new Set(ids).size === ids.length;
	}, "ids must differ");
