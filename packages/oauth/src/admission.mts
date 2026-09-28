/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * What every consumer of session admission in this package shares (the
 * session-admission ADR's D1, D8): the refusal a hand-built factory answers
 * when it is given no requirements resolver, and the token endpoint's shape
 * of a `step_up` refusal — `invalid_grant` with `step_up: "<requirement>"`,
 * RFC 6749's vocabulary with one member beside it (the MFA ADR's D16 row),
 * which the `session`, `authorization_code` and `refresh_token` grants all
 * answer and `/oauth/token` copies onto the wire.
 */

import {
	checkResolver,
	type GrantError,
	type SessionRequirementResolver,
} from "@o3co/auth-provider-core";

/**
 * The resolver a factory was handed, or a throw naming the option: a
 * composition that bypasses the boot planner cannot build a consumer with
 * an empty or home-made resolver. A missing one is refused here, where the
 * operator can read why, not at the first request; one the planner or
 * `resolverForTests` did not build — a copy, an `as` cast, a hand-made
 * object — is refused by core's `checkResolver`, the same check
 * `admitSession` applies, so a forged resolver never decides the acr drop
 * either.
 */
export function requireRequirements(
	factory: string,
	requirements: SessionRequirementResolver | undefined,
): SessionRequirementResolver {
	if (requirements === undefined) {
		throw new Error(
			`${factory}: requirements is required — the sessionRequirementResolver the boot planner built (the manifests pass it), or resolverForTests from @o3co/auth-provider-core/testing in a test`,
		);
	}
	return checkResolver(requirements);
}

/**
 * What an `unavailable` admission is described as, by the store it names
 * (the session-admission ADR's D10): the session store, the revocation
 * boundary's store — the words the token side uses for it — or a registered
 * requirement, whose name is the operator's, in the log line, and not the
 * client's.
 */
export const unavailableDescription = (store: string): string =>
	store === "user_session"
		? "session store unavailable"
		: store === "revocation_boundary"
			? "revocation store unavailable"
			: "session requirement unavailable";

/** The token endpoint's `step_up` refusal: `invalid_grant`, and the requirement that asked, so an updated client can offer the step-up. */
export interface StepUpRefusal extends GrantError {
	readonly status: 400;
	readonly error: "invalid_grant";
	readonly errorDescription: string;
	/** The member `/oauth/token` copies onto the body beside `error` and `error_description`. */
	readonly step_up: string;
}

/**
 * A `step_up` admission as a grant answers it (D8): the session is live and
 * a requirement can be met by a trip a token endpoint cannot send anyone on,
 * so the client re-authenticates the user interactively — `invalid_grant`,
 * with the requirement named in `step_up`.
 */
export const stepUpRefusal = (requirement: string): StepUpRefusal => ({
	status: 400,
	error: "invalid_grant",
	errorDescription: `the session must step up through ${requirement}`,
	step_up: requirement,
});

/** The `step_up` member of a grant's error, when it carries one. */
export const stepUpOf = (result: GrantError): string | undefined => {
	const member = (result as { readonly step_up?: unknown }).step_up;
	return typeof member === "string" && member.length > 0 ? member : undefined;
};
