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

const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";

const algorithms = ["EdDSA", "ES256", "RS256"] as const;

/** The issuer's host, the only one its key set is fetched from; none for an issuer that is no URL. */
const hostsOf = (issuer: string) => (URL.canParse(issuer) ? [new URL(issuer).hostname] : []);

/** A public key only: a private key written here refuses boot rather than being dropped later. */
const readable = (pem: string) => publicPem(pem) !== undefined;

const section = z.strictObject({
	issuers: z
		.array(
			z.union([
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
				}),
				z
					.strictObject({ issuer: z.string().min(1), "jwks-uri": z.string() })
					.refine(
						(i) =>
							withinHosts(i["jwks-uri"], hostsOf(i.issuer)) &&
							new URL(i["jwks-uri"]).protocol === "https:",
						"the key set is not at https on the issuer's host",
					),
			]),
		)
		.prefault([])
		.describe(
			"The trusted issuers: each with its public keys (kid, alg, SPKI PEM), or its key set's URL at https on its host.",
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

const used: Space = {
	name: "jwt-bearer.jti",
	guarantees: ["no-eviction", "durable", "replicated"],
};

/** Kept longer than any assertion is accepted by this much, so clock differences never let one back. */
const usedAllowanceMs = 60_000;

export default defineModule({ name: "jwt-bearer", section }, (m) => [
	m.contribute(spaces).by(() => used),
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
		const trusted = new Map(
			c.section.issuers.map((i) => [
				i.issuer,
				jwt.verifierOf(
					"keys" in i
						? {
								pem: i.keys.map(({ kid, alg, "public-key": pem }) => ({
									alg,
									pem,
									...(kid ? { kid } : {}),
								})),
							}
						: { jwks: { url: i["jwks-uri"], hosts: hostsOf(i.issuer) } },
					{
						algorithms: "keys" in i ? [...new Set(i.keys.map((k) => k.alg))] : algorithms,
						skewMs,
						maxLifetimeMs: c.section["max-assertion-lifetime"] * 1000,
						expect: { aud: [named, url] },
					},
				),
			]),
		);
		return {
			grantType,
			targets: true,
			handle: async ({ client, param, admits, issue, target }) => {
				const assertion = param("assertion");
				if (!assertion)
					return { kind: "error", error: "invalid_request", description: "assertion is required" };
				const checked = await check(assertion, trusted);
				if (checked.kind === "invalid")
					return { kind: "error", error: "invalid_grant", description: checked.reason };
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
