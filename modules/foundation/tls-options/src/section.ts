import { z } from "zod";

/** TLS 1.3's suites, as OpenSSL names them. */
export const tls13Suites = [
	"TLS_AES_256_GCM_SHA384",
	"TLS_CHACHA20_POLY1305_SHA256",
	"TLS_AES_128_GCM_SHA256",
] as const;

/** TLS 1.2's ECDHE suites with an AEAD cipher: never the RSA key exchange nor CBC. */
export const tls12Suites = [
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES256-GCM-SHA384",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-CHACHA20-POLY1305",
	"ECDHE-RSA-CHACHA20-POLY1305",
] as const;

export const section = z
	.strictObject({
		"min-version": z
			.enum(["TLSv1.2", "TLSv1.3"])
			.prefault("TLSv1.2")
			.describe("The least TLS version the provider's own connections take: TLSv1.2 or TLSv1.3."),
		suites: z
			.array(z.enum([...tls13Suites, ...tls12Suites]))
			.min(1)
			.refine((names) => new Set(names).size === names.length, "names each suite once")
			.prefault([...tls13Suites, ...tls12Suites])
			.describe(
				"The suites they take, among TLS 1.3's and TLS 1.2's ECDHE with AES-GCM or ChaCha20-Poly1305: every one by default.",
			),
	})
	.superRefine((s, context) => {
		// Node, missing one version's suites, takes it with its own or drops it, saying nothing: so each
		// version taken names one.
		const named = (suites: readonly string[]) => s.suites.some((name) => suites.includes(name));
		const at = (message: string) => context.addIssue({ code: "custom", path: ["suites"], message });
		if (!named(tls13Suites)) at("name a TLS 1.3 suite");
		if (s["min-version"] === "TLSv1.2" && !named(tls12Suites)) {
			at("name a TLS 1.2 suite, or set min-version to TLSv1.3");
		}
	});

export type Settings = z.output<typeof section>;
