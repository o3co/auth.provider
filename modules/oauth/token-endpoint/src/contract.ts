import { contract } from "@mod/kernel";

export { authenticateClient, oauthError, refusedAuthenticationAnswer } from "./answers/answers.ts";

/** Where the token endpoint answers, absolute on the public origin; nothing without one. */
export interface TokenEndpointLocation {
	readonly url: string | undefined;
}

export const tokenEndpointLocation = contract<TokenEndpointLocation>("token-endpoint.location");
