import type { HttpRequest, HttpResponse } from "@mod/http";
import { oauthError } from "@mod/token-endpoint";

/** The token both routes are asked about, or their answer to a repeated parameter or a missing token. */
export function tokenOf(request: HttpRequest): string | HttpResponse {
	if (request.form.repeated().length > 0) {
		return oauthError(400, "invalid_request", "repeated parameter");
	}
	return request.form.single("token") || oauthError(400, "invalid_request", "token is required");
}
