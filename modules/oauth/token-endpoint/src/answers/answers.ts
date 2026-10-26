/** The answers the OAuth endpoints share: an error response, and a refused client authentication's. */
import type { Audit } from "@mod/audit";
import {
	type Authentication,
	type Client,
	type Clients,
	recordRefusedAuthentication,
} from "@mod/clients";
import type { OAuthError } from "@mod/grants";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";

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

/** The response with these `WWW-Authenticate` challenges (RFC 9110 §11.6.1), or as it is with none. */
export const challenged = (response: HttpResponse, challenges: readonly string[]): HttpResponse =>
	challenges.length > 0
		? { ...response, headers: { ...response.headers, "www-authenticate": challenges.join(", ") } }
		: response;

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
	return { kind: "refused", response: refusedAuthenticationAnswer(authenticated) };
}

/**
 * The answer to a refused authentication: two methods or malformed credentials `400`, any other `401`
 * with its challenges. Where an assertion is part of the two methods or the malformed credentials,
 * `401 invalid_client` with the challenges of the methods tried (RFC 7521 §4.2.1).
 */
export function refusedAuthenticationAnswer(
	refused: Extract<Authentication, { readonly kind: "refused" }>,
): HttpResponse {
	if (refused.assertion) return challenged(oauthError(401, "invalid_client"), refused.challenges);
	if (refused.reason === "multiple_methods") {
		return oauthError(400, "invalid_request", "use one client authentication method");
	}
	if (refused.reason === "malformed_credentials") {
		return oauthError(400, "invalid_request", "malformed client credentials");
	}
	return challenged(oauthError(401, "invalid_client"), refused.challenges);
}
