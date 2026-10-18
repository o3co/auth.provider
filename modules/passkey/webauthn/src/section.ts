import { setting } from "@mod/kernel";
import { z } from "zod";

/** An origin as a browser serializes it: https, or http on localhost; a domain, never an IP literal. */
const origin = z.string().refine((entry) => {
	const url = URL.parse(entry);
	if (!url || url.origin !== entry) return false;
	if (url.hostname.startsWith("[") || /^[\d.]+$/.test(url.hostname)) return false;
	return url.protocol === "https:" || (url.protocol === "http:" && url.hostname === "localhost");
}, "a serialized https origin (http only on localhost), on a domain");

/** An Android app origin: the unpadded base64url SHA-256 of its signing certificate; no host. */
const app = /^android:apk-key-hash:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/** Whether a browser takes `rpId` on `host`: the host, or a domain above it but no single label. */
const servesHost = (rpId: string, host: string) =>
	host === rpId || (host.endsWith(`.${rpId}`) && rpId.includes("."));

export const section = z
	.strictObject({
		"rp-id": z.string().min(1),
		"rp-name": z.string().min(1),
		/** The origins ceremonies may come from, matched exactly. */
		origins: z
			.array(z.union([z.string().regex(app, "an Android app origin of this form"), origin]))
			.min(1),
		/** The pages that may frame a ceremony; none by default, so any ceremony in a frame is refused. */
		"top-origins": z.array(origin).prefault([]),
		"challenge-lifetime": setting
			.duration("s")
			.pipe(z.number().int().min(10).max(600))
			.prefault("2m")
			.describe("How long a ceremony's challenge can be answered, from 10s to 10m."),
		"user-verification": z.enum(["required", "preferred", "discouraged"]).prefault("preferred"),
		"max-credentials": z.number().int().min(1).max(100).prefault(10),
		"challenge-seconds": z
			.number()
			.int()
			.min(10)
			.max(600)
			.optional()
			.describe("Seconds; write `challenge-lifetime` instead."),
	})
	.refine(
		(s) =>
			s.origins.every(
				(entry) => app.test(entry) || servesHost(s["rp-id"], new URL(entry).hostname),
			),
		{
			path: ["rp-id"],
			message: "the host of each web origin, or a domain each one lies under",
		},
	);

export type Settings = z.output<typeof section>;
