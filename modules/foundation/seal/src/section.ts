import { secretBytes } from "@mod/keys";
import { z } from "zod";

/** A key id: it heads every sealed value, so it holds no dot. */
export const keyId = /^[A-Za-z0-9_-]{1,32}$/;

const key = z.strictObject({
	id: z.string().regex(keyId).describe("The key's id, which heads every value it seals."),
	key: secretBytes({ exactly: 32 }).describe("32 bytes, base64, of at least 8 byte values."),
});

const ring = z.strictObject({
	keys: z
		.array(key)
		.min(1)
		.optional()
		.describe("Before current: the first seals, the rest open. Not beside current or previous."),
	current: key.optional().describe("The key that seals; any key of the ring opens."),
	next: key
		.optional()
		.describe("Opens but never seals, so every host opens with it before it seals."),
	previous: z.array(key).prefault([]).describe("Keys that only open what they sealed."),
});

/** The ring a section names: `keys` read as `current` first and `previous` after. */
export const section = ring
	.refine((s) => (s.keys === undefined) !== (s.current === undefined), "either keys or current")
	.refine((s) => s.keys === undefined || s.previous.length === 0, "keys stands alone of previous")
	.transform((s) => {
		const listed = s.keys ?? (s.current ? [s.current, ...s.previous] : []);
		const [current, ...previous] = listed;
		return { current: current as z.output<typeof key>, next: s.next, previous };
	})
	.refine((s) => {
		const ids = [s.current, ...(s.next ? [s.next] : []), ...s.previous].map((k) => k.id);
		return new Set(ids).size === ids.length;
	}, "ids must differ");
