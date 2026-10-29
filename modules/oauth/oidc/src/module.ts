import { hintReaders } from "@mod/authorize";
import { claimScopes, claimsSelections } from "@mod/claims-selection";
import { documentCopies } from "@mod/client-documents";
import { metadataSections } from "@mod/clients";
import { idTokens } from "@mod/code-grant";
import { issuer, metadata } from "@mod/issuer";
import { contract, defineModule, setting } from "@mod/kernel";
import { isVerifyAlgorithm, keys } from "@mod/keys";
import { type SubjectAttributes, subjectAttributes } from "@mod/subject-attributes";
import { userAttribute } from "@mod/users";
import { z } from "zod";
import { clientCopyOf, clientSectionOf, requiredAlg } from "./alg.ts";
import { claimsOf, scopeOfClaim, tableClaims, tableScopes } from "./claims/table.ts";
import { idTokenHints, type ReleasedClaims, releasedClaims } from "./contract.ts";
import { hintReaderOf, hintsOver } from "./hints.ts";

const section = z.strictObject({
	"id-token-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(86_400))
		.prefault("1h")
		.describe("How long an ID token lasts: a duration with a unit, e.g. 1h."),
	"id-token-alg": z
		.string()
		.refine(isVerifyAlgorithm, "a JWS algorithm")
		.prefault(requiredAlg)
		.describe(
			"The JWS algorithm ID tokens are signed with, which `keys` must sign with: RS256 unless written. Another warns at each start, as OpenID Connect Discovery 1.0 §3 has RS256 listed.",
		),
});

/** The algorithm ID tokens are signed with, the operator's, checked against keys once each boot. */
const idTokenAlg = contract<string>("oidc.id-token-alg");

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
	{
		name: "oidc",
		replicaSafe: true,
		section,
		takes: [subjectAttributes, keys, issuer, claimsSelections],
	},
	(m) => [
		m.provide(idTokenAlg).by(async (c) => {
			const signer = await c.get(keys);
			// ID tokens are checked by others with the public key; a shared secret could forge them.
			if (!signer.asymmetric()) {
				return c.refuse("oidc", "ID tokens need an asymmetric signing key");
			}
			const signed = signer.algorithm();
			const alg = c.section["id-token-alg"];
			if (alg !== signed) {
				return c.refuse(
					"oidc.id-token-alg",
					`keys signs with ${signed}, not oidc.id-token-alg's ${alg}: add an ${alg} key as keys.signing, or set id-token-alg to ${signed}`,
				);
			}
			if (alg !== requiredAlg) c.log.warn("oidc.id_token_alg_not_rs256", { alg });
			// Not refused: a rotation to another algorithm publishes its key as the next one first.
			const next = signer.nextAlgorithm();
			if (next !== undefined && next !== alg) {
				c.log.warn("oidc.next_key_alg_differs", {
					reason: `keys.next signs with ${next}, not oidc.id-token-alg's ${alg}: when it becomes keys.signing, set id-token-alg to ${next} with it`,
				});
			}
			return alg;
		}),
		m.contribute(metadataSections).by(async (c) => clientSectionOf(await c.get(idTokenAlg))),
		m
			.contribute(documentCopies)
			.by(async (c) => clientCopyOf(clientSectionOf(await c.get(idTokenAlg)))),
		m.provide(releasedClaims).by(async (c) => releasedOver(await c.get(subjectAttributes))),
		m
			.provide(idTokenHints)
			.by(async (c) => hintsOver({ keys: await c.get(keys), issuer: (await c.get(issuer)).url })),
		m
			.contribute(hintReaders)
			.by(async (c) =>
				hintReaderOf(hintsOver({ keys: await c.get(keys), issuer: (await c.get(issuer)).url })),
			),
		m.contribute(idTokens).by(async (c) => {
			// Every client's ID tokens: a client naming another algorithm is refused by its section.
			await c.get(idTokenAlg);
			const signer = await c.get(keys);
			const issuerUrl = (await c.get(issuer)).url;
			const lifetime = c.section["id-token-lifetime"];
			const released = releasedOver(await c.get(subjectAttributes));
			const selections = await c.get(claimsSelections);
			return {
				scope: openid,
				make: async (r) => {
					// The redemption's pinned selection; one whose pin is gone fails, never released unconstrained.
					const selection = await selections.forCode(r.redemption);
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
			value: [await c.get(idTokenAlg)],
		})),
	],
);
