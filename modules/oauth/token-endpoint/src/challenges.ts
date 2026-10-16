import type { AuthMethod, Client } from "@mod/clients";
import type { HttpResponse } from "@mod/http";

/** The response with these `WWW-Authenticate` challenges (RFC 9110 §11.6.1), or as it is with none. */
export const challenged = (response: HttpResponse, challenges: readonly string[]): HttpResponse =>
	challenges.length > 0
		? { ...response, headers: { ...response.headers, "www-authenticate": challenges.join(", ") } }
		: response;

/** A client's challenges: its method's (RFC 6749 §5.2), or every method's when it declares none. */
export const challengesOf = (methods: readonly AuthMethod[], client: Client): readonly string[] => {
	const own = methods.find((method) => method.name === client.method)?.challenge;
	return own ? [own] : methods.flatMap((method) => (method.challenge ? [method.challenge] : []));
};
