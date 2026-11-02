import { defineModule, setting } from "@o3co/auth-provider-foundation/kernel";
import { clientAllowance } from "@o3co/auth-provider-oauth/client-allowance";
import { type Grant, grants } from "@o3co/auth-provider-oauth/grants";
import { issuer } from "@o3co/auth-provider-oauth/issuer";
import { lifetimeSecondsRange, tokens } from "@o3co/auth-provider-oauth/tokens";
import { z } from "zod";

/** The grant type a client names; a URI, as RFC 6749 asks of an extension grant. */
const grantType = "urn:example:params:oauth:grant-type:example";

/** The longest an access token of this grant may live, the operator's to lower. */
const section = z.strictObject({
	"access-token-ceiling": setting
		.duration("s")
		.pipe(z.number().int().min(lifetimeSecondsRange.min).max(lifetimeSecondsRange.max))
		.prefault("1h"),
});

/** A confidential client's token for itself, within what its allowance lets it ask. */
const example = (issuerUrl: string): Grant => ({
	grantType,
	readsAmbient: "none",
	handle: async ({ client, param, issue }) => {
		if (client.kind !== "confidential") return { kind: "error", error: "unauthorized_client" };
		const allowed = clientAllowance.allowedIssuance(client, param("scope"), issuerUrl);
		if (allowed.kind === "error") return allowed;
		const { scope, audience } = allowed;
		const issued = await issue({ subject: client.id, issuedTo: client.id, audience, scope });
		if (issued.kind === "refused") return issued;
		const { token, tokenType, expiresIn } = issued.access;
		return {
			kind: "issued",
			body: {
				access_token: token,
				token_type: tokenType,
				expires_in: expiresIn,
				scope: scope.join(" "),
			},
		};
	},
});

// Safe on many instances: it keeps nothing across requests.
export default defineModule(
	{ name: "example-grant", section, replicaSafe: true, takes: [issuer, tokens] },
	(m) => [
		m.contribute(grants).by(async (c) => {
			// Read at build time: the lifetime `issue` applies where this grant gives none is fixed by now.
			const lifetime = (await c.get(tokens)).accessTokenLifetimeSeconds();
			if (lifetime > c.section["access-token-ceiling"]) {
				// Settings by their keys, never their values.
				return c.refuse(
					"example-grant.access-token-ceiling",
					"tokens.access-token-lifetime is over it: lower that, or raise this",
				);
			}
			return example((await c.get(issuer)).url);
		}),
	],
);
