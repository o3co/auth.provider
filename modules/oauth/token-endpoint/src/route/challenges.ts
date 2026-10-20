import type { HttpResponse } from "@mod/http";

/** The response with these `WWW-Authenticate` challenges (RFC 9110 §11.6.1), or as it is with none. */
export const challenged = (response: HttpResponse, challenges: readonly string[]): HttpResponse =>
	challenges.length > 0
		? { ...response, headers: { ...response.headers, "www-authenticate": challenges.join(", ") } }
		: response;
