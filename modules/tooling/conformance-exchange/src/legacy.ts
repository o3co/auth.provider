import { onLegacy } from "@mod/conformance-legacy";
import { oauthArea } from "@mod/conformance-oauth";
import { exchangeArea } from "./area.ts";

onLegacy(exchangeArea, {
	// The standalone build loads neither token exchange nor DPoP; the composed entry adds them.
	map: (part, scene) => {
		const dpop = oauthArea.in(scene)?.dpop === true;
		return {
			env: {
				...(part.maxActorDepth
					? { OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH: String(part.maxActorDepth) }
					: {}),
				...(part.maxLifetimeSeconds
					? { OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN: String(part.maxLifetimeSeconds) }
					: {}),
				// The build refuses a cap below its default lifetime (3600 s), so the default comes down with it.
				...(part.maxLifetimeSeconds && part.maxLifetimeSeconds < 3600
					? { OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN: String(part.maxLifetimeSeconds) }
					: {}),
			},
			settings: dpop ? "dpop { enabled = true }\n" : "",
			extra: ["token-exchange", ...(dpop ? ["dpop"] : [])],
		};
	},
	differs: [
		// With a verified email required, token exchange does not start over a users file, and its
		// refusal of an unverified subject is invalid_request.
		"email-gate-without-subject-lookup",
		"email-refusal-code-exchange",
		// Ours takes the lifetime asked as o3co_expires_in (RFC 6749 §8.2); the legacy build reads expires_in.
		"lifetime-asked-as-expires-in",
	],
});
