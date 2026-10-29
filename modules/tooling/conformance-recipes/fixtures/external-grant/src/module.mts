import { defineModule } from "@o3co/auth-provider-foundation/kernel";
import { clientAllowance } from "@o3co/auth-provider-oauth/client-allowance";
import { type Grant, grants } from "@o3co/auth-provider-oauth/grants";
import { issuer } from "@o3co/auth-provider-oauth/issuer";

/** The grant type a client names; a URI, as RFC 6749 asks of an extension grant. */
const grantType = "urn:example:params:oauth:grant-type:example";

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
export default defineModule({ name: "example-grant", replicaSafe: true, takes: [issuer] }, (m) => [
	m.contribute(grants).by(async (c) => example((await c.get(issuer)).url)),
]);
