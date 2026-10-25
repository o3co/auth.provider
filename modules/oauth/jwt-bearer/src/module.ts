import { createHash } from "node:crypto";
import { clientAllowance } from "@mod/client-allowance";
import { grants } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { defineModule, setting } from "@mod/kernel";
import { revocations } from "@mod/subject-revocation";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { z } from "zod";
import { check } from "./assertion/assertion.ts";
import { algorithms, linkedIssuers, linkedSubjects, spentAssertions } from "./contract.ts";
import {
	type IssuerEntry,
	issuersIn,
	issuersSetting,
	issuersTakes,
	linkedOf,
	selfIssuedOf,
} from "./issuers/issuers.ts";
import { spentIn } from "./ledgers.ts";

/** The grant type it serves (RFC 7523). */
export const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";

const section = z.strictObject({
	issuers: issuersSetting,
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
	linkedSubjects,
	...issuersTakes,
];

export default defineModule({ name: "jwt-bearer", section, takes }, (m) => [
	m
		.provide(linkedIssuers)
		.by((c) =>
			[...linkedOf(c.section.issuers)].map(([issuer, upstream]) => ({ upstream, issuer })),
		),

	m.contribute(grants).by(async (c) => {
		const named = (await c.get(issuer)).url;
		const { url } = await c.get(tokenEndpointLocation);
		if (url === undefined) {
			return c.refuse("jwt-bearer", "the token endpoint's location needs a public origin");
		}
		const spent = await c.get(spentAssertions);
		const boundaries = await c.get(revocations);
		const skewMs = c.section["clock-skew"] * 1000;
		const policyOf = (i: IssuerEntry) => ({
			algorithms: "keys" in i ? [...new Set(i.keys.map((k) => k.alg))] : algorithms,
			skewMs,
			maxLifetimeMs: c.section["max-assertion-lifetime"] * 1000,
			expect: { aud: [named, url] },
		});
		const trust = await issuersIn(c, c.section.issuers, policyOf);
		if (trust.kind === "refused") return c.refuseAll(trust.refusals);
		const { trusted, ledgers } = trust;
		const selfIssued = selfIssuedOf(c.section.issuers);
		// Told once, by place: the prefixes are the operator's, never written out.
		if (selfIssued.length > 0) {
			c.log.info("jwt-bearer.self_issued_signers", {
				at: selfIssued.map((s) => s.where).join(","),
			});
		}
		const linked = linkedOf(c.section.issuers);
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
