import { setting } from "@mod/kernel";
import { hostEntryOf } from "@mod/outbound-policy";
import { z } from "zod";
import type { RevocationPolicy } from "./pki/contract.ts";
import { isCertificate } from "./pki/pki.ts";

const positive = (max: number, fallback: number) =>
	z.number().int().min(1).max(max).prefault(fallback);

/** A time in whole units of `unit`, written with its unit, from `min` to `max` of them. */
const time = (unit: "s" | "ms", min: number, max: number, fallback: string) =>
	setting.duration(unit).pipe(z.number().int().min(min).max(max)).prefault(fallback);

/** How a certificate's revocation is confirmed; `mode` is required, `disabled` confirms none. */
const revocation = z.discriminatedUnion("mode", [
	z.strictObject({
		mode: z
			.literal("disabled")
			.describe(
				"Where revocation is asked: `disabled` confirms none; `crl`, `ocsp` or `both` ask what a certificate names.",
			),
	}),
	z.strictObject({
		mode: z
			.enum(["crl", "ocsp", "both"])
			.describe(
				"Where it is asked: the CRLs, the OCSP responders, or both, that a certificate names.",
			),
		"on-unavailable": z
			.enum(["reject", "allow"])
			.describe("Required: whether an outage refuses the binding, or binds with a warning."),
		hosts: z
			.array(
				z
					.string()
					.refine(
						(entry) => hostEntryOf(entry) !== undefined,
						"not a host, or a name led by a dot",
					),
			)
			.min(1)
			.describe(
				"Required: the only hosts revocation material is fetched from; `.name` covers the name and the names under it.",
			),
		nonce: z.boolean().prefault(true).describe("Whether an OCSP request carries a nonce."),
		skew: time("s", 0, 3600, "5m").describe(
			"How far ahead of this host's clock revocation material may say it was issued, from 0s to 1h.",
		),
		"ocsp-fresh": time("s", 1, 86_400, "10m").describe(
			"How long an OCSP answer without a next update is taken, from 1s to 1d.",
		),
		"crl-ttl": time("s", 1, 86_400, "1h").describe(
			"How long a CRL is kept at most, its next update aside, from 1s to 1d.",
		),
		"failure-lifetime": time("s", 1, 3600, "30s").describe(
			"How long a source that failed is not asked again, from 1s to 1h.",
		),
		"crl-entries": positive(65_536, 256).describe("How many CRLs are kept."),
		"ocsp-entries": positive(65_536, 1024).describe("How many OCSP answers are kept."),
		timeout: time("ms", 1, 60_000, "3s").describe("How long one fetch may take, from 1ms to 1m."),
		"max-fetches": positive(64, 4).describe(
			"How many sources one check may fetch from; past them, what is left is unconfirmed.",
		),
	}),
]);

const modeText =
	"How a client certificate binds: `self-signed` binds any certificate that parses; `pki` checks a path to an anchor.";

/** `mode` is required: `self-signed` binds any certificate that parses; `pki` checks a path to an anchor. */
export const section = z.discriminatedUnion("mode", [
	z.strictObject({ mode: z.literal("self-signed").describe(modeText) }),
	z.strictObject({
		mode: z.literal("pki").describe(modeText),
		anchors: z
			.array(z.string().min(1))
			.min(1)
			.describe("The trust anchors, as PEM text holding one certificate each."),
		"max-intermediates": z
			.number()
			.int()
			.min(0)
			.max(14)
			.prefault(4)
			.describe("At most this many certificates between the leaf and an anchor."),
		"min-rsa-bits": z
			.number()
			.int()
			.min(2048)
			.max(16_384)
			.prefault(2048)
			.describe("The fewest bits an RSA key in the path may have; 2048 at least."),
		revocation: revocation.describe("How a certificate's revocation is confirmed."),
	}),
]);

/** An anchor's DER from PEM text holding one certificate block and nothing else. */
export function anchorOf(pem: string): Uint8Array | undefined {
	const pattern = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g;
	const [only, ...more] = [...pem.matchAll(pattern)];
	if (!only || more.length > 0 || pem.replace(pattern, "").trim() !== "") return undefined;
	const der = new Uint8Array(Buffer.from((only[1] ?? "").replace(/\s+/g, ""), "base64"));
	return isCertificate(der) ? der : undefined;
}

type PkiSection = Extract<z.output<typeof section>, { mode: "pki" }>;
type RevocationSection = Exclude<PkiSection["revocation"], { mode: "disabled" }>;

/** The revocation policy a PKI section states, in milliseconds. */
export const revocationPolicyOf = (r: RevocationSection): RevocationPolicy => ({
	mode: r.mode,
	nonce: r.nonce,
	skewMs: r.skew * 1000,
	ocspFreshMs: r["ocsp-fresh"] * 1000,
	crlTtlMs: r["crl-ttl"] * 1000,
	failureMs: r["failure-lifetime"] * 1000,
	crlEntries: r["crl-entries"],
	ocspEntries: r["ocsp-entries"],
	maxFetches: r["max-fetches"],
});
