import { createHash } from "node:crypto";
import { clientAllowance } from "@mod/client-allowance";
import { externalJwt } from "@mod/external-jwt";
import { grants } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { defineModule, type Refusal, setting } from "@mod/kernel";
import { publicPem } from "@mod/keys";
import { withinHosts } from "@mod/outbound-policy";
import { revocations } from "@mod/subject-revocation";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { z } from "zod";
import { check } from "./assertion/assertion.ts";
import {
	algorithms,
	jtiLedgers,
	linkedIssuers,
	linkedSubjects,
	signerKeys,
	spentAssertions,
} from "./contract.ts";
import { spentIn } from "./ledgers.ts";
import { contributedSigners, fetchedSigners, type Signers, writtenSigners } from "./signers.ts";

/** The grant type it serves (RFC 7523). */
export const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/** The issuer's host, the only one its key set is fetched from; none for an issuer that is no URL. */
const hostsOf = (issuer: string) => (URL.canParse(issuer) ? [new URL(issuer).hostname] : []);

/** A public key only: a private key written here refuses boot rather than being dropped later. */
const readable = (pem: string) => publicPem(pem) !== undefined;

/** How an issuer's assertion names the subject a token is for. */
const subjectOf = {
	subject: z
		.enum(["as-is", "linked"])
		// Required, but checked past the union of key sources, so a refusal names this key.
		.optional()
		.describe(
			'Required. "as-is": the assertion\'s `sub` is the subject. "linked": the user `users` finds by the upstream identity (`upstream`, `sub`) is.',
		),
	upstream: z
		.string()
		.min(1)
		.optional()
		.describe('The IdP name `users` knows this issuer\'s signers by; written with "linked" only.'),
	"subject-is-key-thumbprint": z
		.boolean()
		.prefault(false)
		.describe(
			"Whether `sub` must be the JWK thumbprint (RFC 7638, SHA-256) of the key that signed.",
		),
	"self-issued-prefix": z
		.string()
		.regex(/^[\x21-\x7e]{1,64}$/, "1 to 64 printable ASCII characters")
		.optional()
		.describe(
			"Takes self-issued signers too: an assertion whose `iss` and `sub` are both this prefix and its key's JWK thumbprint, read as this issuer's. Needs `subject-is-key-thumbprint` and keys contributed.",
		),
};

const issuerEntry = z
	.union([
		z.strictObject({
			issuer: z.string().min(1),
			keys: z
				.array(
					z.strictObject({
						kid: z.string().min(1).optional(),
						alg: z.enum(algorithms),
						"public-key": z
							.string()
							.refine(readable, "not readable as a public key PEM (a private key is refused)"),
					}),
				)
				.min(1),
			...subjectOf,
		}),
		z
			.strictObject({ issuer: z.string().min(1), "jwks-uri": z.string(), ...subjectOf })
			.refine(
				(i) =>
					withinHosts(i["jwks-uri"], hostsOf(i.issuer)) &&
					new URL(i["jwks-uri"]).protocol === "https:",
				"the key set is not at https on the issuer's host",
			)
			.refine(
				(i) => !i["subject-is-key-thumbprint"],
				"a key set fetched here cannot tell which key signed: subject-is-key-thumbprint needs keys written or contributed",
			),
		z.strictObject({ issuer: z.string().min(1), ...subjectOf }),
	])
	.refine((i) => i.subject !== undefined, {
		message: 'required: "as-is" or "linked"',
		path: ["subject"],
	})
	.refine((i) => (i.subject === "linked") === (i.upstream !== undefined), {
		message: 'upstream is written with subject = "linked", and only then',
		path: ["upstream"],
	})
	.refine(
		(i) =>
			i["self-issued-prefix"] === undefined ||
			(i["subject-is-key-thumbprint"] && !("keys" in i) && !("jwks-uri" in i)),
		{
			message: "a self-issued prefix needs subject-is-key-thumbprint and keys contributed",
			path: ["self-issued-prefix"],
		},
	);

/** Refusals of prefixes that could read one assertion as two issuers', each at its place, whatever the order. */
function prefixRefusals(
	issuers: readonly { issuer: string; "self-issued-prefix"?: string | undefined }[],
) {
	const at = (i: number) => `jwt-bearer.issuers.${i}`;
	const refused: Refusal[] = [];
	for (const [a, own] of issuers.entries()) {
		const prefix = own["self-issued-prefix"];
		if (prefix === undefined) continue;
		const where = `${at(a)}.self-issued-prefix`;
		for (const [b, other] of issuers.entries()) {
			if (other.issuer.startsWith(prefix)) {
				refused.push({ where, reason: `starts the issuer of ${at(b)}` });
			}
			const theirs = other["self-issued-prefix"];
			if (
				b !== a &&
				theirs !== undefined &&
				(theirs.startsWith(prefix) || prefix.startsWith(theirs))
			) {
				refused.push({ where, reason: `overlaps the self-issued prefix of ${at(b)}` });
			}
		}
	}
	return refused;
}

const section = z.strictObject({
	issuers: z
		.array(issuerEntry)
		.prefault([])
		.describe(
			"The trusted issuers: each with its public keys (kid, alg, SPKI PEM), its key set's URL at https on its host, or neither, its keys then contributed at `signerKeys`.",
		),
	"max-assertion-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1h")
		.describe("The longest lifetime an assertion may claim, from `1s` to `1d` in whole seconds."),
	"clock-skew": setting
		.duration("s")
		.pipe(z.number().int().min(0).max(300))
		.prefault("30s")
		.describe(
			"How far an assertion's times may be off this host's clock, from `0s` to `5m` in whole seconds.",
		),
});

/** Each linked issuer, by the IdP name its signers are known by. */
const linkedOf = (s: z.output<typeof section>): ReadonlyMap<string, string> =>
	new Map(s.issuers.flatMap((i) => (i.upstream ? [[i.issuer, i.upstream] as const] : [])));

/** Kept longer than any assertion is accepted by this much, so clock differences never let one back. */
const usedAllowanceMs = 60_000;

/** A spent assertion's name; JSON keeps the issuer and the jti apart, whatever either holds. */
const spentName = (issuer: string, jti: string) =>
	createHash("sha256")
		.update(JSON.stringify([issuer, jti]))
		.digest("base64url");

/** What the grant takes; its own `linkedIssuers` is not named, its own points it collects are. */
const takes = [
	issuer,
	tokenEndpointLocation,
	spentAssertions,
	revocations,
	externalJwt,
	signerKeys,
	linkedSubjects,
	jtiLedgers,
];

export default defineModule({ name: "jwt-bearer", section, takes }, (m) => [
	m
		.provide(linkedIssuers)
		.by((c) => [...linkedOf(c.section)].map(([issuer, upstream]) => ({ upstream, issuer }))),

	m.contribute(grants).by(async (c) => {
		const named = (await c.get(issuer)).url;
		const { url } = await c.get(tokenEndpointLocation);
		if (url === undefined) {
			return c.refuse("jwt-bearer", "the token endpoint's location needs a public origin");
		}
		const spent = await c.get(spentAssertions);
		const boundaries = await c.get(revocations);
		const jwt = await c.get(externalJwt);
		const skewMs = c.section["clock-skew"] * 1000;
		const contributed = new Map((await c.collect(signerKeys)).map((k) => [k.issuer, k]));
		const policyOf = (i: (typeof c.section.issuers)[number]) => ({
			algorithms: "keys" in i ? [...new Set(i.keys.map((k) => k.alg))] : algorithms,
			skewMs,
			maxLifetimeMs: c.section["max-assertion-lifetime"] * 1000,
			expect: { aud: [named, url] },
		});
		const trusted = new Map<string, Signers>();
		// Named by its place in the settings, never by its value: a refusal tells no setting's value.
		const refused: Refusal[] = [];
		const firstAt = new Map<string, number>();
		for (const [at, i] of c.section.issuers.entries()) {
			const where = `jwt-bearer.issuers.${at}`;
			const first = firstAt.get(i.issuer);
			if (first === undefined) firstAt.set(i.issuer, at);
			else refused.push({ where, reason: `names the same issuer as jwt-bearer.issuers.${first}` });
			const keys = contributed.get(i.issuer);
			const written = "keys" in i || "jwks-uri" in i;
			if (written && keys) refused.push({ where, reason: "has its keys written and contributed" });
			if (!written && !keys) refused.push({ where, reason: "has no keys written or contributed" });
			const thumbprint = i["subject-is-key-thumbprint"];
			trusted.set(
				i.issuer,
				"keys" in i
					? await writtenSigners(
							jwt,
							i.keys.map(({ kid, alg, "public-key": pem }) => ({
								alg,
								pem,
								...(kid ? { kid } : {}),
							})),
							policyOf(i),
							thumbprint,
						)
					: "jwks-uri" in i
						? fetchedSigners(jwt, { url: i["jwks-uri"], hosts: hostsOf(i.issuer) }, policyOf(i))
						: contributedSigners(jwt, keys as NonNullable<typeof keys>, policyOf(i), thumbprint),
			);
		}
		refused.push(...prefixRefusals(c.section.issuers));
		const ledgers = new Map((await c.collect(jtiLedgers)).map((l) => [l.issuer, l]));
		for (const [what, named] of [
			["keys are", [...contributed.keys()]],
			["jti ledgers are", [...ledgers.keys()]],
		] as const) {
			const unnamed = named.filter((name) => !trusted.has(name)).length;
			if (unnamed > 0) {
				refused.push({
					where: "jwt-bearer.issuers",
					reason: `${what} contributed for ${unnamed} issuer${unnamed === 1 ? "" : "s"} none of these names: name ${unnamed === 1 ? "it" : "them"} here, or leave out the module that contributes them`,
				});
			}
		}
		if (refused.length > 0) return c.refuseAll(refused);
		const selfIssued = c.section.issuers.flatMap((i, at) =>
			i["self-issued-prefix"] === undefined ? [] : [`jwt-bearer.issuers.${at}`],
		);
		// Told once, by place: the prefixes are the operator's, never written out.
		if (selfIssued.length > 0)
			c.log.info("jwt-bearer.self_issued_signers", { at: selfIssued.join(",") });
		const linked = linkedOf(c.section);
		const resolvers = await c.collect(linkedSubjects);
		if (linked.size > 0 && resolvers.length === 0) {
			return c.refuse(
				"jwt-bearer.issuers",
				"a linked issuer needs its subjects resolved: compose users, which brings jwt-bearer-users",
			);
		}
		if (resolvers.length > 1) {
			const by = resolvers.map((r) => r.declaredBy).join(", ");
			return c.refuse("jwt-bearer", `more than one module resolves linked subjects: ${by}`);
		}
		const [resolver] = resolvers;
		/** The subject a verified signer stands for: its sub, or for a linked issuer the one resolved, none where none is. */
		const subjectOf = async (from: string, sub: string) => {
			const name = linked.get(from);
			if (name === undefined || resolver === undefined) return sub;
			const found = await resolver.subjectOf(name, sub);
			return found.kind === "subject" ? found.subject : undefined;
		};
		return {
			grantType: jwtBearerGrantType,
			readsAmbient: "none",
			targets: true,
			handle: async ({ client, param, admits, issue, target }) => {
				const assertion = param("assertion");
				if (!assertion)
					return { kind: "error", error: "invalid_request", description: "assertion is required" };
				const verified = await check(assertion, trusted);
				if (verified.kind === "invalid")
					return { kind: "error", error: "invalid_grant", description: verified.reason };
				const subject = await subjectOf(verified.issuer, verified.subject);
				if (subject === undefined)
					return { kind: "error", error: "invalid_grant", description: "unknown subject" };
				const checked = { ...verified, subject };
				const allowed = clientAllowance.allowedIssuance(client, param("scope"), named);
				if (allowed.kind === "error") return allowed;
				const asked = target(allowed.audience, (a) =>
					clientAllowance.allowsAudience(client, a, named),
				);
				if (asked.kind === "error") return asked;
				// Made at its `iat`, never later than now; one that does not say is as old as can be. The
				// boundary is widened by the skew allowed, as an issuer's clock may run that far ahead.
				const madeAt = Math.min(checked.issuedAt ?? 0, c.clock.now());
				if ((await boundaries.compare(checked.subject, madeAt, "sessions", skewMs)) === "revoked") {
					return { kind: "error", error: "invalid_grant", description: "assertion revoked" };
				}
				const { scope } = allowed;
				const { audience } = asked;
				const access = { subject: checked.subject, issuedTo: client.id, audience, scope };
				// Asked before the jti is used up, so a refusal leaves the assertion usable.
				const admitted = await admits(access);
				if (admitted.kind === "refused") return admitted;
				const keepUntil = checked.expiresAt + skewMs + usedAllowanceMs;
				// An issuer with a ledger uses its jti up there alone, never the store, whatever it answers.
				const ledger = ledgers.get(checked.issuer);
				const told = ledger
					? await spentIn(ledger, {
							sentIssuer: checked.issuer,
							jti: checked.jti,
							expiresAt: checked.expiresAt,
							keepUntil,
						})
					: // Relative, since the store judges a lifetime by its own clock.
						await spent.save(spentName(checked.issuer, checked.jti), keepUntil - c.clock.now());
				if (told === "replayed" || told === "exists")
					return { kind: "error", error: "invalid_grant", description: "assertion replayed" };
				const issued = await issue(access, { notAfter: checked.expiresAt });
				if (issued.kind === "refused") return issued;
				const token = issued.access;
				return {
					kind: "issued",
					body: {
						access_token: token.token,
						token_type: token.tokenType,
						expires_in: token.expiresIn,
						scope: scope.join(" "),
					},
				};
			},
		};
	}),
]);
