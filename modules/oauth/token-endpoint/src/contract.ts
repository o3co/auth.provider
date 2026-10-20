import type { Audit } from "@mod/audit";
import { type Client, type Clients, recordRefusedAuthentication } from "@mod/clients";
import type { OAuthError } from "@mod/grants";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { contract } from "@mod/kernel";
import { challenged } from "./route/challenges.ts";

/** The built-in grant's type (RFC 6749 §4.4). */
export const clientCredentialsGrantType = "client_credentials";

/** Where the token endpoint answers, absolute on the public origin; nothing without one. */
export interface TokenEndpointLocation {
	readonly url: string | undefined;
}

export const tokenEndpointLocation = contract<TokenEndpointLocation>("token-endpoint.location");

/** RFC 6749 §5.2: `error_description` is printable ASCII but `"` and `\`; any other character shows as `?`. */
const printable = (text: string) => text.replace(/[^\x20-\x21\x23-\x5b\x5d-\x7e]/g, "?");

/** Names an error body never takes from its members: the error's (RFC 6749 §5.2) and a success's (§5.1). */
const reserved = new Set([
	"error",
	"error_description",
	"access_token",
	"token_type",
	"expires_in",
	"refresh_token",
	"scope",
]);

/** RFC 6749 §5.2: `error_uri` is a URI of printable characters but space, `"` and `\`. */
const isErrorUri = (value: unknown) =>
	typeof value === "string" && /^[\x21\x23-\x5b\x5d-\x7e]+$/.test(value) && URL.canParse(value);

export function oauthError(
	status: number,
	/** An OAuth error code; other modules may answer with codes they own, such as a binding's. */
	error: OAuthError | "temporarily_unavailable" | (string & {}),
	description?: string,
	/** More members of the body, read by nobody here; a reserved name or a malformed `error_uri` is dropped. */
	members?: Readonly<Record<string, unknown>>,
): HttpResponse {
	return jsonAnswer(status, {
		...Object.fromEntries(
			Object.entries(members ?? {}).filter(
				([name, value]) => !reserved.has(name) && (name !== "error_uri" || isErrorUri(value)),
			),
		),
		error,
		...(description ? { error_description: printable(description) } : {}),
	});
}

/** Authenticates the request's client; a refusal is recorded on `audit` once, by its reason and the source alone. */
export async function authenticateClient(
	clients: Clients,
	request: HttpRequest,
	audit: Pick<Audit, "record">,
): Promise<
	| {
			readonly kind: "client";
			readonly client: Client;
			/** `clients`' challenges for a later 401 to this client. */
			readonly challenges: readonly string[];
	  }
	| { readonly kind: "refused"; readonly response: HttpResponse }
> {
	const authenticated = await clients.authenticate(request);
	if (authenticated.kind === "authenticated") {
		return { kind: "client", client: authenticated.client, challenges: authenticated.challenges };
	}
	recordRefusedAuthentication(audit, request, authenticated);
	if (authenticated.reason === "multiple_methods") {
		return {
			kind: "refused",
			response: oauthError(400, "invalid_request", "use one client authentication method"),
		};
	}
	if (authenticated.reason === "malformed_credentials") {
		return {
			kind: "refused",
			response: oauthError(400, "invalid_request", "malformed client credentials"),
		};
	}
	return {
		kind: "refused",
		response: challenged(oauthError(401, "invalid_client"), authenticated.challenges),
	};
}
