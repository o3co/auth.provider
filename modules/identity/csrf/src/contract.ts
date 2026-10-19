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
