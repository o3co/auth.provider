import { secretBytes } from "@mod/keys";
import { z } from "zod";

/** A key id: it heads every sealed value, so it holds no dot. */
export const keyId = /^[A-Za-z0-9_-]{1,32}$/;

const key = z.strictObject({
	id: z.string().regex(keyId).describe("The key's id, which heads every value it seals."),
	key: secretBytes({ exactly: 32 }).describe("32 bytes, base64, of at least 8 byte values."),
});

export const section = z.strictObject({
	keys: z
		.array(key)
		.min(1)
		.refine((keys) => new Set(keys.map((k) => k.id)).size === keys.length, "ids must differ")
		.describe("The sealing keys. The first seals; all open."),
});
