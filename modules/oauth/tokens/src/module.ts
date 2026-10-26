import { type AddedClaims, addedClaimsIn, addedClaimsOf } from "@mod/added-claims";
import { site } from "@mod/http";
import { issuer, metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { accessTokenSigning, keys } from "@mod/keys";
import { senderBinding } from "@mod/sender-binding";
import { denylistAllowanceMs, denylistOver, revokedTokens } from "@mod/token-denylist";
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
import { type IssueAccess, issuing, judging } from "./issuance/issuance.ts";
import { chainWithin, expiryOf, issuedWithin, keptGrant, lifetimeOf, tokenId } from "./limits.ts";
import { namedBy } from "./reference.ts";
import { section } from "./section.ts";

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

/** The longest compact access token tokens issues or reads, so it always takes what it issued. */
const compactLimit = 16_384;
/** Whether a payload's actor chain is within the depth tokens issues. */
const actorsWithin = (act: unknown) => chainWithin(act, (link) => (link as { act?: unknown }).act);
type Valid = Extract<AccessCheck, { kind: "valid" }>;
type Invalid = Extract<AccessCheck, { kind: "invalid" }>;
type Checked =
	| { readonly kind: "checked"; readonly access: Valid; readonly issuedAt: number }
	| Invalid;

/** A kept grant as claims; the added ones, `act`, `amr`, `auth_time` and `acr` only when given. */
const grantClaims = (grant: AccessGrant) => ({
	// None can stand for a name below: a grant adds no reserved name.
	...grant.claims,
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

/** The grant read back from verified claims, and the claims its grant added. */
const grantOf = (claims: Claims, added: AddedClaims | undefined): AccessGrant =>
	Object.freeze({
		subject: claims.sub,
		issuedTo: claims.client_id,
		audience: Object.freeze(typeof claims.aud === "string" ? [claims.aud] : claims.aud),
		scope: Object.freeze(claims.scope ? claims.scope.split(" ") : []),
		...(claims.act ? { actor: actorOf(claims.act) } : {}),
		...(claims.amr ? { amr: Object.freeze(claims.amr) } : {}),
		...(claims.auth_time === undefined ? {} : { authenticatedAt: claims.auth_time * 1000 }),
		...(claims.acr === undefined ? {} : { acr: claims.acr }),
		...(added ? { claims: added } : {}),
	});

/** The added claims of a verified payload, copied as an issue copies them; undefined for a token none of tokens' issued. */
const addedOf = (payload: Readonly<Record<string, unknown>>) => {
	try {
		return { added: addedClaimsOf(addedClaimsIn(payload)) };
	} catch (error) {
		if (error instanceof TypeError) return undefined;
		throw error;
	}
};

/** Whether the section keeps revoked access tokens in a denylist, which takes token-denylist's store. */
const denylisted = (s: { readonly revocation: "denylist" | "unsupported" }) =>
	s.revocation === "denylist";

export default defineModule(
	{
		name: "tokens",
		section,
		takes: (s) => [
			site,
			keys,
			accessTokenSigning,
			senderBinding,
			subjectChecks,
			accessConditions,
			issuer,
			issuancePolicies,
			...(denylisted(s) ? [revokedTokens] : []),
		],
	},
	(m) => [
		// Access tokens are signed by keys, which publishes the key set they are checked with.
		m.contribute(metadata).by(async (c) => {
			const origin = (await c.get(site)).origin;
			const path = (await c.get(keys)).keySetPath();
			return { name: "jwks_uri", value: origin && new URL(path, origin).href };
		}),
		m.provide(tokens).by(async (c) => {
			const signing = await c.get(accessTokenSigning);
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
				denylisted(c.section) ? await c.get(revokedTokens) : undefined,
				c.clock,
			);
			const iss = (await c.get(issuer)).url;
			const lifetime = c.section["access-token-lifetime"];

			/** Verifies everything but revocation; `allowanceMs` keeps a just-expired token valid. */
			const check = async (token: string, allowanceMs = 0): Promise<Checked> => {
				if (token.length > compactLimit) return { kind: "invalid", reason: "shape" };
				const verified = await signing.verify(token);
				if (verified.kind === "invalid") return { kind: "invalid", reason: "signature" };
				// Taken from the payload as signed, before the shape drops what it does not name: a member
				// reserved and never written, or one outside the rules, is no token of tokens'.
				const extra = addedOf(verified.claims);
				if (!extra || !actorsWithin(verified.claims.act))
					return { kind: "invalid", reason: "shape" };
				const parsed = claimsShape.safeParse(verified.claims);
				if (!parsed.success) return { kind: "invalid", reason: "shape" };
				const claims = parsed.data;
				if (claims.iss !== iss) return { kind: "invalid", reason: "issuer" };
				if (claims.exp * 1000 + allowanceMs <= c.clock.now())
					return { kind: "invalid", reason: "expired" };
				// Times tokens never issues: a token signed past it, or whose iat moved, is no token of tokens'.
				if (!issuedWithin(claims.iat, claims.exp, c.clock.now())) {
					return { kind: "invalid", reason: "shape" };
				}
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
						grant: grantOf(claims, extra.added),
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
				const token = await signing.sign(claims);
				// Its standard claims have no cap of their own: one past what tokens reads is never answered.
				if (token.length > compactLimit) {
					throw new TypeError(`tokens: the access token is over ${compactLimit} bytes`);
				}
				return {
					token,
					id: claims.jti,
					expiresAt: exp * 1000,
					expiresIn: exp - iat,
					tokenType: limits?.binding?.tokenType ?? "Bearer",
					...(grant.claims ? { addedClaims: Object.freeze(Object.keys(grant.claims).sort()) } : {}),
				};
			};
			const access: Tokens = {
				revocable: () => denylist.revocable,
				accessTokenLifetimeSeconds: () => lifetime,
				...issuing(judge, issueAccess, c.clock.now),
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
	],
);
