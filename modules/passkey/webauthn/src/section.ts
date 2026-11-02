import { setting } from "@mod/kernel";
import { z } from "zod";
import { algorithmNames } from "./ceremony/ceremony.ts";

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
		"rp-id": z
			.string()
			.min(1)
			.describe("The relying party ID: each web origin's host, or a domain each one lies under."),
		"rp-name": z
			.string()
			.min(1)
			.describe("The relying party's name, as an authenticator shows it."),
		origins: z
			.array(z.union([z.string().regex(app, "an Android app origin of this form"), origin]))
			.min(1)
			.describe(
				"The origins ceremonies may come from, matched exactly: https web origins (http only on localhost, with `kernel.environment = development`), or Android app origins.",
			),
		"top-origins": z
			.array(origin)
			.prefault([])
			.describe(
				"The pages that may frame a ceremony; none by default, so any ceremony in a frame is refused.",
			),
		"challenge-lifetime": setting
			.duration("s")
			.pipe(z.number().int().min(10).max(600))
			.prefault("2m")
			.describe("How long a ceremony's challenge can be answered, from 10s to 10m."),
		algorithms: z
			.array(z.enum(algorithmNames))
			.min(1)
			.refine((names) => new Set(names).size === names.length, "names each algorithm once")
			.prefault([...algorithmNames])
			.describe(
				"The signature algorithms a passkey may use, offered at registration in this order: EdDSA, ES256 or RS256, at least one. A passkey of one left out can no longer sign in.",
			),
	})
	// An entry that is no URL is the origins' own refusal: this never reads one, whether or not zod
	// runs it past a field that failed.
	.refine(
		(s) =>
			s.origins.every(
				(entry) =>
					app.test(entry) ||
					!URL.canParse(entry) ||
					servesHost(s["rp-id"], new URL(entry).hostname),
			),
		{
			path: ["rp-id"],
			message: "the host of each web origin, or a domain each one lies under",
		},
	);

export type Settings = z.output<typeof section>;
