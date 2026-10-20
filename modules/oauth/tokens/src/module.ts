import { site } from "@mod/http";
import { issuer, metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { keys } from "@mod/keys";
import { senderBinding } from "@mod/sender-binding";
import { z } from "zod";
import {
	type AccessCheck,
	type AccessGrant,
	type Actor,
	accessConditions,
	issuancePolicies,
	subjectChecks,
	type Tokens,
	tokens,
} from "./contract.ts";
import { denylistAllowanceMs, denylistOver } from "./denylist/denylist.ts";
import { type IssueAccess, issuing, judging } from "./issuance.ts";
import { expiryOf, keptGrant, lifetimeOf, tokenId } from "./limits.ts";
import { namedBy } from "./reference.ts";
import { section } from "./section.ts";
import { revokedTokens } from "./store.ts";

interface Act {
	readonly sub: string;
	readonly act?: Act | undefined;
}
const actShape: z.ZodType<Act> = z.lazy(() =>
	z.object({ sub: z.string(), act: actShape.optional() }),
);

const actOf = (actor: Actor): Act => ({
	sub: actor.subject,
	...(actor.actor ? { act: actOf(actor.actor) } : {}),
});
const actorOf = (act: Act): Actor =>
	Object.freeze({ subject: act.sub, ...(act.act ? { actor: actorOf(act.act) } : {}) });

const claimsShape = z.object({
	iss: z.string(),
	sub: z.string(),
	aud: z.union([z.string(), z.array(z.string())]),
	client_id: z.string(),
	scope: z.string().optional(),
	exp: z.number(),
	iat: z.number(),
	jti: z.string().min(1),
	cnf: z.record(z.string(), z.string()).optional(),
	act: actShape.optional(),
	amr: z.array(z.string()).optional(),
	auth_time: z.number().optional(),
	acr: z.string().min(1).optional(),
});

type Claims = z.infer<typeof claimsShape>;
type Valid = Extract<AccessCheck, { kind: "valid" }>;
type Invalid = Extract<AccessCheck, { kind: "invalid" }>;
type Checked =
	| { readonly kind: "checked"; readonly access: Valid; readonly issuedAt: number }
	| Invalid;

/** A kept grant as claims; `act`, `amr`, `auth_time` and `acr` only when given. */
const grantClaims = (grant: AccessGrant) => ({
	sub: grant.subject,
	aud: grant.audience.length === 1 ? grant.audience[0] : grant.audience,
	client_id: grant.issuedTo,
	...(grant.scope.length > 0 ? { scope: grant.scope.join(" ") } : {}),
	...(grant.actor ? { act: actOf(grant.actor) } : {}),
	...(grant.amr ? { amr: grant.amr } : {}),
	...(grant.authenticatedAt === undefined || grant.authenticatedAtUnknown
		? {}
		: { auth_time: grant.authenticatedAt / 1000 }),
	...(grant.acr === undefined ? {} : { acr: grant.acr }),
});

/** The grant read back from verified claims. */
const grantOf = (claims: Claims): AccessGrant =>
	Object.freeze({
		subject: claims.sub,
		issuedTo: claims.client_id,
		audience: Object.freeze(typeof claims.aud === "string" ? [claims.aud] : claims.aud),
		scope: Object.freeze(claims.scope ? claims.scope.split(" ") : []),
		...(claims.act ? { actor: actorOf(claims.act) } : {}),
		...(claims.amr ? { amr: Object.freeze(claims.amr) } : {}),
		...(claims.auth_time === undefined ? {} : { authenticatedAt: claims.auth_time * 1000 }),
		...(claims.acr === undefined ? {} : { acr: claims.acr }),
	});

export default defineModule({ name: "tokens", section }, (m) => [
	// Access tokens are signed by keys, which publishes the key set they are checked with.
	m.contribute(metadata).by(async (c) => {
		const origin = (await c.get(site)).origin;
		const path = (await c.get(keys)).keySetPath();
		return { name: "jwks_uri", value: origin && new URL(path, origin).href };
	}),
	m.provide(tokens).by(async (c) => {
		const signer = await c.get(keys);
		const bindings = await c.get(senderBinding);
		const subjects = await c.collect(subjectChecks);
		// Exactly one module checks subject revocation, or the operator states that none does.
		const unchecked = c.section["subject-check"] === "none";
		if (unchecked && subjects.length > 0) {
			return c.refuse(
				"tokens.subject-check",
				"the section states that subjects are not checked, yet a module checks them",
			);
		}
		if (!unchecked && subjects.length !== 1) {
			return c.refuse(
				"tokens.subject-check",
				"needs exactly one module that checks subject revocation, or the section stating none",
			);
		}
		const conditions = [...(await c.collect(accessConditions)), ...subjects];
		const denylist = denylistOver(
			c.section.revocation === "denylist" ? await c.get(revokedTokens) : undefined,
			c.clock,
		);
		const iss = (await c.get(issuer)).url;
		const lifetime = c.section["access-token-lifetime"];

		/** Verifies everything but revocation; `allowanceMs` keeps a just-expired token valid. */
		const check = async (token: string, allowanceMs = 0): Promise<Checked> => {
			const verified = await signer.verify(token, "at+jwt");
			if (verified.kind === "invalid") return { kind: "invalid", reason: "signature" };
			const parsed = claimsShape.safeParse(verified.claims);
			if (!parsed.success) return { kind: "invalid", reason: "shape" };
			const claims = parsed.data;
			if (claims.iss !== iss) return { kind: "invalid", reason: "issuer" };
			if (claims.exp * 1000 + allowanceMs <= c.clock.now())
				return { kind: "invalid", reason: "expired" };
			const bound = Object.entries(claims.cnf ?? {}).map(([member, confirmation]) => ({
				member,
				confirmation,
			}));
			if (bound.length > 1) return { kind: "invalid", reason: "shape" };
			const [binding] = bound;
			const tokenType = binding ? bindings.tokenTypeOf(binding.member) : "Bearer";
			if (!tokenType) return { kind: "invalid", reason: "shape" };
			return {
				kind: "checked",
				issuedAt: claims.iat * 1000,
				access: {
					kind: "valid",
					id: claims.jti,
					expiresAt: claims.exp * 1000,
					tokenType,
					...(binding ? { binding: { ...binding, tokenType } } : {}),
					grant: grantOf(claims),
				},
			};
		};

		const timeout = c.section["issuance-timeout"];
		const judge = judging(await c.collect(issuancePolicies), c.clock.now, () =>
			AbortSignal.timeout(timeout),
		);
		const issueAccess: IssueAccess = async (grant, limits) => {
			const lifetimeSeconds = lifetimeOf(limits?.lifetimeSeconds, lifetime);
			const { iat, exp } = expiryOf(c.clock.now(), lifetimeSeconds, limits?.notAfter);
			const claims = {
				iss,
				...grantClaims(keptGrant(grant, iat)),
				iat,
				exp,
				jti: tokenId(c.random),
				...(limits?.binding
					? { cnf: { [limits.binding.member]: limits.binding.confirmation } }
					: {}),
			};
			return {
				token: await signer.sign(claims, "at+jwt"),
				id: claims.jti,
				expiresAt: exp * 1000,
				expiresIn: exp - iat,
				tokenType: limits?.binding?.tokenType ?? "Bearer",
			};
		};
		const access: Tokens = {
			revocable: () => denylist.revocable,
			...issuing(judge, issueAccess),
			verifyAccess: async (token) => {
				const checked = await check(token);
				if (checked.kind === "invalid") return checked;
				if (await denylist.holds(checked.access.id)) {
					return { kind: "invalid", reason: "revoked" };
				}
				const issuedFor = {
					id: checked.access.id,
					subject: checked.access.grant.subject,
					issuedAt: checked.issuedAt,
				};
				for (const condition of conditions) {
					if ((await condition.holds(issuedFor)) === "revoked") {
						return { kind: "invalid", reason: "revoked" };
					}
				}
				return checked.access;
			},
			issuedToOf: async (token) => {
				const checked = await check(token, denylistAllowanceMs);
				return checked.kind === "invalid"
					? { kind: "invalid" }
					: { kind: "issued", issuedTo: checked.access.grant.issuedTo };
			},
			revokeReferenced: async (reference) => {
				const referenced = namedBy(reference);
				return referenced
					? denylist.revoke(referenced.id, referenced.expiresAt)
					: { kind: "invalid" };
			},
			revokeAccess: async (token) => {
				if (!denylist.revocable) return { kind: "unsupported" };
				// A host whose clock is behind may still take a just-expired token as valid.
				const checked = await check(token, denylistAllowanceMs);
				if (checked.kind === "invalid") return { kind: "invalid" };
				return denylist.revoke(checked.access.id, checked.access.expiresAt);
			},
		};
		return access;
	}),
]);
