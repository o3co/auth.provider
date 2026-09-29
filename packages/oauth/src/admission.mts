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
 * The token endpoint's `step_up` refusal, shared by every consumer of session
 * admission in this package (see ADR 2026-09-28-session-admission):
 * `invalid_grant` with one member beside RFC 6749's, `step_up:
 * "<requirement>"`. The `session`, `authorization_code` and `refresh_token`
 * grants answer it and `/oauth/token` copies it onto the wire. A hand-built
 * factory's missing or forged requirements resolver is refused by core's
 * `checkResolver(value, factory)`, which every consumer factory runs at
 * construction.
 */

import type { GrantError } from "@o3co/auth-provider-core";

/** The token endpoint's `step_up` refusal: `invalid_grant`, and the requirement that asked, so an updated client can offer the step-up. */
export interface StepUpRefusal extends GrantError {
	readonly status: 400;
	readonly error: "invalid_grant";
	readonly errorDescription: string;
	/** The member `/oauth/token` copies onto the body beside `error` and `error_description`. */
	readonly step_up: string;
}

/**
 * A `step_up` admission as a grant answers it: the session is live and
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
