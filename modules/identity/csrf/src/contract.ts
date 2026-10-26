import { type HttpRequest, type HttpResponse, jsonAnswer, policy } from "@mod/http";
import { contract } from "@mod/kernel";

/** The policy a route uses to refuse cross-site requests: a GET passes; any other method needs the evidence. */
export const csrfChecked = policy("csrf");

/** The answer to a request the policy refuses. */
export const csrfRefused: HttpResponse = Object.freeze(jsonAnswer(403, { error: "csrf" }));

/** Whether a request shows positive evidence that it came from this deployment's origin. */
export interface OriginEvidence {
	/** True only when `Origin` is the public origin or `Sec-Fetch-Site` is `same-origin`, and nothing says otherwise. */
	sameOrigin(request: HttpRequest): boolean;
}

export const originEvidence = contract<OriginEvidence>("csrf.origin-evidence");

/** A double-submit token for a form the server draws itself, which posts it in a field. */
export interface FormTokens {
	/**
	 * The field to send it in, the token, and the cookie that pairs with it; a valid token the request
	 * holds is kept, so a form open in another tab stays usable.
	 */
	issue(request: HttpRequest): {
		readonly field: string;
		readonly token: string;
		readonly cookies: readonly string[];
	};
}

export const formTokens = contract<FormTokens>("csrf.form-tokens");
