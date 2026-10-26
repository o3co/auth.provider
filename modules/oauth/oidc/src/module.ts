import { claimScopes, claimsSelections } from "@mod/claims-selection";
import { idTokens } from "@mod/code-grant";
import { issuer, metadata } from "@mod/issuer";
import { defineModule, setting } from "@mod/kernel";
import { keys } from "@mod/keys";
import { type SubjectAttributes, subjectAttributes } from "@mod/subject-attributes";
import { userAttribute } from "@mod/users";
import { z } from "zod";
import { claimsOf, scopeOfClaim, tableClaims, tableScopes } from "./claims/table.ts";
import { idTokenHints, type ReleasedClaims, releasedClaims } from "./contract.ts";
import { hintsOver } from "./hints.ts";

const section = z.strictObject({
	"id-token-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(86_400))
		.prefault("1h")
		.describe("How long an ID token lasts: a duration with a unit, e.g. 1h."),
});

const nothing = Object.freeze({});

/** The scope that brings an ID token; it releases no claims of its own, so it is not in the table. */
const openid = "openid";

// Read on each request, from whichever source subject-attributes answers with. Only what users
// vouches for may say the email is verified: an upstream verified an address it controls, which
// need not be this user's, so its word on that is left out.
const releasedOver = (read: SubjectAttributes): ReleasedClaims => ({
	of: async (subject, scope, handle, asked) => {
		const found = await read.of(subject, handle);
		if (found.kind === "unknown") return nothing;
		const { [userAttribute.emailVerified]: _, ...unvouched } = found.attributes;
		return claimsOf(found.vouched ? found.attributes : unvouched, scope, asked);
	},
});

export default defineModule(
	{ name: "oidc", section, takes: [subjectAttributes, keys, issuer, claimsSelections] },
	(m) => [
		m.provide(releasedClaims).by(async (c) => releasedOver(await c.get(subjectAttributes))),
		m
			.provide(idTokenHints)
			.by(async (c) => hintsOver({ keys: await c.get(keys), issuer: (await c.get(issuer)).url })),
		m.contribute(idTokens).by(async (c) => {
			const signer = await c.get(keys);
			// ID tokens are checked by others with the public key; a shared secret could forge them.
			if (!signer.asymmetric()) {
				return c.refuse("oidc", "ID tokens need an asymmetric signing key");
			}
			const issuerUrl = (await c.get(issuer)).url;
			const lifetime = c.section["id-token-lifetime"];
			const released = releasedOver(await c.get(subjectAttributes));
			const selections = await c.get(claimsSelections);
			return {
				scope: openid,
				make: async (r) => {
					// The redemption's pinned selection; one whose pin is gone fails, never released unconstrained.
					const selection =
						r.redemption === undefined ? undefined : await selections.forCode(r.redemption);
					const claims = await released.of(r.subject, r.scope, r.session, selection?.idToken);
					const iat = Math.floor(c.clock.now() / 1000);
					return signer.sign(
						{
							// First, so no table claim can stand for one set below.
							...claims,
							iss: issuerUrl,
							sub: r.subject,
							aud: r.clientId,
							azp: r.clientId,
							iat,
							exp: iat + lifetime,
							// An authentication time nobody vouches for is never claimed.
							...(r.authenticatedAtUnknown
								? {}
								: { auth_time: Math.min(iat, Math.floor(r.authenticatedAt / 1000)) }),
							amr: [...r.amr],
							// OpenID Connect Front-Channel and Back-Channel Logout 1.0: the session's handle, which never lets anyone into it.
							sid: r.session,
							...(r.nonce !== undefined ? { nonce: r.nonce } : {}),
							...(r.acr !== undefined ? { acr: r.acr } : {}),
						},
						"JWT",
					);
				},
			};
		}),
		// The table's scopes, so a claims request's names are selected by them.
		m.contribute(claimScopes).by(() => ({ scopeOf: scopeOfClaim })),
		m
			.contribute(metadata)
			.by(() => ({ name: "scopes_supported", value: [openid, ...tableScopes] })),
		// The claims about the user (OpenID Connect Core §5.1): `sub`, and those the table can release.
		m.contribute(metadata).by(() => ({ name: "claims_supported", value: ["sub", ...tableClaims] })),
		// `sub` is the user's subject, the same for every client.
		m.contribute(metadata).by(() => ({ name: "subject_types_supported", value: ["public"] })),
		// ID tokens are signed with keys' current key alone.
		m.contribute(metadata).by(async (c) => ({
			name: "id_token_signing_alg_values_supported",
			value: [(await c.get(keys)).algorithm()],
		})),
	],
);
