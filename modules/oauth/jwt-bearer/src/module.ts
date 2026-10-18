import { clientAllowance } from "@mod/client-allowance";
import { externalJwt } from "@mod/external-jwt";
import { grants } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { defineModule, setting } from "@mod/kernel";
import { publicPem } from "@mod/keys";
import { withinHosts } from "@mod/outbound";
import { type Space, spaces, store } from "@mod/store";
import { revocations } from "@mod/subject-revocation";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { z } from "zod";
import { check } from "./assertion.ts";
import { algorithms, linkedIssuers, linkedSubjects, signerKeys } from "./contract.ts";
import { contributedSigners, fetchedSigners, type Signers, writtenSigners } from "./signers.ts";

const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";

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
	});

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

const used: Space = {
	name: "jwt-bearer.jti",
	guarantees: ["no-eviction", "durable", "replicated"],
};

/** Kept longer than any assertion is accepted by this much, so clock differences never let one back. */
const usedAllowanceMs = 60_000;

export default defineModule({ name: "jwt-bearer", section }, (m) => [
	m.contribute(spaces).by(() => used),
	m
		.provide(linkedIssuers)
		.by((c) => [...linkedOf(c.section)].map(([issuer, upstream]) => ({ upstream, issuer }))),

	m.contribute(grants).by(async (c) => {
		const named = (await c.get(issuer)).url;
		const { url } = await c.get(tokenEndpointLocation);
		if (url === undefined) {
			return c.refuse("jwt-bearer", "the token endpoint's location needs a public origin");
		}
		const saved = await c.get(store);
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
		const refused: string[] = [];
		for (const i of c.section.issuers) {
			const keys = contributed.get(i.issuer);
			const written = "keys" in i || "jwks-uri" in i;
			if (written && keys) refused.push(`${i.issuer} has its keys written and contributed`);
			if (!written && !keys) refused.push(`${i.issuer} has no keys written or contributed`);
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
		if (refused.length > 0) return c.refuse("jwt-bearer.issuers", refused.join("; "));
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
			grantType,
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
				// Made at its `iat`, never later than now; one that does not say is as old as can be.
				const madeAt = Math.min(checked.issuedAt ?? 0, c.clock.now());
				if ((await boundaries.compare(checked.subject, madeAt, "sessions")) === "revoked") {
					return { kind: "error", error: "invalid_grant", description: "assertion revoked" };
				}
				const { scope } = allowed;
				const { audience } = asked;
				const access = { subject: checked.subject, issuedTo: client.id, audience, scope };
				// Asked before the jti is used up, so a refusal leaves the assertion usable.
				const admitted = await admits(access);
				if (admitted.kind === "refused") return admitted;
				const first = await saved.putIfAbsent(
					{ space: used, partition: checked.issuer, name: checked.jti },
					true,
					// Relative, since the store judges expiry by its own clock.
					{
						expiry: {
							kind: "after",
							ms: checked.expiresAt + skewMs - c.clock.now() + usedAllowanceMs,
						},
					},
				);
				if (first.kind !== "written")
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
						...(scope.length > 0 ? { scope: scope.join(" ") } : {}),
					},
				};
			},
		};
	}),
]);
