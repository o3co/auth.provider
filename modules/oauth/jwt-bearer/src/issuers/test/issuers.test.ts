import { generateKeyPairSync } from "node:crypto";
import type { ExternalJwt, KeySource } from "@mod/external-jwt";
import { describe, expect, it } from "vitest";
import { type IssuerEntry, issuersSetting, trustedWith } from "../issuers.ts";

const pem = generateKeyPairSync("ed25519")
	.publicKey.export({ format: "pem", type: "spki" })
	.toString();
const written = {
	issuer: "https://a.example",
	subject: "as-is",
	keys: [{ alg: "EdDSA", "public-key": pem }],
};
const fetched = {
	issuer: "https://b.example",
	subject: "as-is",
	"jwks-uri": "https://b.example/jwks",
};
const contributed = { issuer: "https://c.example", subject: "as-is" };
const read = (entry: Record<string, unknown>) => issuersSetting.safeParse([entry]);
/** Conditions, so an entry whose every signer becomes a subject boots for what else a test asks of it. */
const held = { conditions: { "subject-prefix": "s-" } };

/** An external-jwt that records the key sources asked of it. */
function recording() {
	const sources: KeySource[] = [];
	const jwt = {
		algorithms: [],
		verifierOf: (source: KeySource) => {
			sources.push(source);
			return { verify: async () => ({ kind: "invalid", reason: "signature" }) };
		},
	} as unknown as ExternalJwt;
	return { jwt, sources };
}
const section = { "max-assertion-lifetime": 3600, "clock-skew": 30 };
const trust = (issuers: readonly IssuerEntry[], jwt = recording().jwt) =>
	trustedWith({
		jwt,
		issuers,
		section,
		contributed: [],
		ledgers: [],
		policyOf: () => ({ algorithms: ["EdDSA"], skewMs: 0 }),
	});
const parsed = (entry: Record<string, unknown>) => {
	const r = read(entry);
	if (!r.success) throw new Error(JSON.stringify(r.error.issues));
	return r.data;
};

describe("an entry's algorithms", () => {
	it("takes algorithms past the defaults for a key set or contributed keys, never beside written keys", () => {
		expect(read({ ...fetched, algorithms: ["PS256", "RS256"] }).success).toBe(true);
		expect(read({ ...contributed, algorithms: ["ES384"] }).success).toBe(true);
		expect(read({ ...written, algorithms: ["EdDSA"] }).success).toBe(false);
		expect(read({ ...fetched, algorithms: [] }).success).toBe(false);
		for (const alg of ["HS256", "none"])
			expect(read({ ...fetched, algorithms: [alg] }).success).toBe(false);
		// A written key may name any algorithm there is to take.
		const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 })
			.publicKey.export({ format: "pem", type: "spki" })
			.toString();
		expect(read({ ...written, keys: [{ alg: "PS256", "public-key": rsa }] }).success).toBe(true);
	});
});

describe("a key set elsewhere", () => {
	it("takes a key set off the issuer's host only where the entry accepts it, and at https always", async () => {
		const elsewhere = { ...fetched, "jwks-uri": "https://keys.example/jwks" };
		expect(read(elsewhere).success).toBe(false);
		expect(read({ ...elsewhere, "accept-key-set-elsewhere": true }).success).toBe(true);
		expect(
			read({
				...elsewhere,
				"jwks-uri": "http://keys.example/jwks",
				"accept-key-set-elsewhere": true,
			}).success,
		).toBe(false);
		expect(read({ ...written, "accept-key-set-elsewhere": true }).success).toBe(false);
		const { jwt, sources } = recording();
		const told = await trust(
			parsed({ ...elsewhere, ...held, "accept-key-set-elsewhere": true }),
			jwt,
		);
		expect(sources).toEqual([
			{ jwks: { url: "https://keys.example/jwks", hosts: ["keys.example"] } },
		]);
		// Warned at its place, never by the URL.
		expect(told).toMatchObject({
			kind: "trusted",
			warnings: [{ event: "jwt-bearer.key_set_elsewhere", where: "jwt-bearer.issuers.0" }],
		});
		expect(JSON.stringify(told.kind === "trusted" ? told.warnings : [])).not.toContain(
			"keys.example",
		);
		expect(await trust(parsed({ ...fetched, ...held }))).toMatchObject({
			kind: "trusted",
			warnings: [],
		});
	});
});

describe("an entry's ceiling", () => {
	it("takes a ceiling naming a list, none of them empty", () => {
		expect(read({ ...written, ceiling: { scopes: ["deploy"] } }).success).toBe(true);
		expect(read({ ...written, ceiling: { audiences: ["https://api"] } }).success).toBe(true);
		for (const ceiling of [
			{},
			{ scopes: [] },
			{ audiences: [] },
			{ scopes: ["a"], audiences: [] },
			{ other: ["a"] },
		]) {
			expect(read({ ...written, ceiling }).success, JSON.stringify(ceiling)).toBe(false);
		}
	});
});

describe("an entry's lifetime and clock skew", () => {
	it("narrows the section's, and refuses one wider, at its place", async () => {
		expect(
			await trust(
				parsed({ ...written, ...held, "max-assertion-lifetime": "10m", "clock-skew": "5s" }),
			),
		).toMatchObject({
			kind: "trusted",
		});
		expect(
			await trust(
				parsed({ ...written, ...held, "max-assertion-lifetime": "1h", "clock-skew": "30s" }),
			),
		).toMatchObject({
			kind: "trusted",
		});
		expect(await trust(parsed({ ...written, ...held, "max-assertion-lifetime": "2h" }))).toEqual({
			kind: "refused",
			refusals: [
				{
					where: "jwt-bearer.issuers.0.max-assertion-lifetime",
					reason: "is longer than the section's",
				},
			],
		});
		expect(await trust(parsed({ ...written, ...held, "clock-skew": "31s" }))).toEqual({
			kind: "refused",
			refusals: [
				{ where: "jwt-bearer.issuers.0.clock-skew", reason: "is wider than the section's" },
			],
		});
		expect(read({ ...written, "clock-skew": "6m" }).success).toBe(false);
	});
});

describe("an issuer whose every signer becomes a subject", () => {
	const conditions = { "subject-prefix": "repo:acme/" };
	const keysFor = (issuer: string, perSigner?: true) => ({
		issuer,
		...(perSigner ? { perSigner } : {}),
		keysOf: async () => ({ kind: "none" as const }),
	});
	const trustWith = (
		entry: Record<string, unknown>,
		contributions: ReturnType<typeof keysFor>[] = [],
	) =>
		trustedWith({
			jwt: recording().jwt,
			issuers: parsed(entry),
			section,
			contributed: contributions,
			ledgers: [],
			policyOf: () => ({ algorithms: ["EdDSA"], skewMs: 0 }),
		});
	const needs = {
		where: "jwt-bearer.issuers.0",
		reason:
			"an issuer whose every signer becomes a subject needs conditions, or accept-any-subject",
	};

	it("takes accept-any-subject alone, warning of it each boot at its place, never by its issuer", async () => {
		const told = await trustWith({ ...written, "accept-any-subject": true });
		expect(told).toEqual(
			expect.objectContaining({
				kind: "trusted",
				warnings: [{ event: "jwt-bearer.any_subject", where: "jwt-bearer.issuers.0" }],
			}),
		);
		expect(JSON.stringify(told.kind === "trusted" ? told.warnings : [])).not.toContain("a.example");
		expect(await trustWith({ ...written, conditions, "accept-any-subject": true })).toEqual({
			kind: "refused",
			refusals: [
				{
					where: "jwt-bearer.issuers.0.accept-any-subject",
					reason: "is written beside conditions",
				},
			],
		});
		expect(
			await trustWith({
				...written,
				subject: "linked",
				upstream: "idp",
				"accept-any-subject": true,
			}),
		).toEqual({
			kind: "refused",
			refusals: [
				{
					where: "jwt-bearer.issuers.0.accept-any-subject",
					reason: "is for an issuer whose every signer becomes a subject",
				},
			],
		});
	});

	it("reads conditions as the conditions module does, refusing ones that hold no predicate", () => {
		expect(read({ ...written, conditions: {} }).success).toBe(false);
		expect(read({ ...written, conditions: { claims: { aud: "x" } } }).success).toBe(false);
	});
});
