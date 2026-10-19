import { clientAllowance } from "@mod/client-allowance";
import type { Grant } from "@mod/grants";
import { clientCredentialsGrantType } from "./contract.ts";

export function clientCredentials(issuer: string): Grant {
	return {
		grantType: clientCredentialsGrantType,
		targets: true,
		handle: async ({ client, param, issue, target }) => {
			if (client.kind !== "confidential") return { kind: "error", error: "unauthorized_client" };
			const allowed = clientAllowance.allowedIssuance(client, param("scope"), issuer);
			if (allowed.kind === "error") return allowed;
			const { scope } = allowed;
			const asked = target(allowed.audience, (a) =>
				clientAllowance.allowsAudience(client, a, issuer),
			);
			if (asked.kind === "error") return asked;
			const { audience } = asked;
			// Nothing is used up before issuing, so `issue` alone asks the policies.
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
	};
}
