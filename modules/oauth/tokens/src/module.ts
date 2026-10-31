import { endpointOrigin, issuer, metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { accessTokenSigning, keys } from "@mod/keys";
import { senderBinding } from "@mod/sender-binding";
import { denylistAllowanceMs, denylistOver, revokedTokens } from "@mod/token-denylist";
import {
	type AccessGrant,
	type Actor,
	accessConditions,
	issuancePolicies,
	subjectChecks,
	type Tokens,
	tokens,
} from "./contract.ts";
import { type IssueAccess, issuing, judging } from "./issuance/issuance.ts";
import { expiryOf, keptGrant, lifetimeOf, tokenId } from "./limits.ts";
import { namedBy } from "./reference.ts";
import { section } from "./section.ts";
import { type Act, checkingWith, compactLimit } from "./verification.ts";

const actOf = (actor: Actor): Act => ({
	sub: actor.subject,
	...(actor.actor ? { act: actOf(actor.actor) } : {}),
});

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

/** Whether the section keeps revoked access tokens in a denylist, which takes token-denylist's store. */
const denylisted = (s: { readonly revocation: "denylist" | "unsupported" }) =>
	s.revocation === "denylist";

export default defineModule(
	{
		name: "tokens",
		replicaSafe: true,
		section,
		takes: (s) => [
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
			const origin = endpointOrigin(await c.get(issuer));
			const path = (await c.get(keys)).keySetPath();
			return { name: "jwks_uri", value: new URL(path, origin).href };
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
			// The operator's choices, yet said at every start: a revoked subject's tokens live on; no
			// access token issued can be revoked.
			if (unchecked) {
				c.log.warn("tokens.subjects_unchecked", {
					reason: "a revoked subject's access tokens are taken until they expire",
				});
			}
			if (!denylisted(c.section)) {
				c.log.warn("tokens.revocation_unsupported", {
					reason: "an access token issued cannot be revoked before it expires",
				});
			}
			const conditions = [...(await c.collect(accessConditions)), ...subjects];
			const denylist = denylistOver(
				denylisted(c.section) ? await c.get(revokedTokens) : undefined,
				c.clock,
			);
			const iss = (await c.get(issuer)).url;
			const lifetime = c.section["access-token-lifetime"];

			const check = checkingWith({ signing, bindings, iss, now: c.clock.now });

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
				// Nothing kept: a token is signed and handed back, no store or record written.
				return {
					access: {
						token,
						id: claims.jti,
						expiresAt: exp * 1000,
						expiresIn: exp - iat,
						tokenType: limits?.binding?.tokenType ?? "Bearer",
						...(grant.claims
							? { addedClaims: Object.freeze(Object.keys(grant.claims).sort()) }
							: {}),
					},
				};
			};
			const access: Tokens = {
				revocable: () => denylist.revocable,
				subjectsChecked: () => !unchecked,
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
