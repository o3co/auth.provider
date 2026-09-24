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
 * The body the session routes answer a redirect policy's refusal with.
 *
 * A policy — this package's allowlist validator, or one a module contributes
 * — names the status, the code and the description. Core's `errorEnvelope`
 * holds the text to RFC 6749's characters and answers a malformed code
 * `server_error`, which is right under a 5xx; under the 4xx a refusal almost
 * always is, it would make a contradictory `400 server_error`. The refusal is
 * still a verdict on the client's `redirect_to`, so a malformed code under a
 * 4xx is answered `invalid_request` here, as `tokenBindingMw` and
 * `/oauth/token`'s grant-policy deny do, and logged.
 */

import {
	auditErrorText,
	type ErrorEnvelope,
	errorEnvelope,
	isWellFormedErrorCode,
	type Logger,
} from "@o3co/auth-provider-core";

/** What a redirect policy refuses with (`FederationResult`'s failure). */
export interface PolicyRefusal {
	readonly status: number;
	readonly error: string;
	readonly errorDescription: string;
}

export function refusalEnvelope(refusal: PolicyRefusal, logger: Logger): ErrorEnvelope {
	const clientError = refusal.status >= 400 && refusal.status < 500;
	if (clientError && !isWellFormedErrorCode(refusal.error)) {
		logger.warn(
			{
				status: refusal.status,
				error: auditErrorText(refusal.error) ?? `(${typeof refusal.error})`,
			},
			"redirect_policy_error_malformed",
		);
		return errorEnvelope("invalid_request", refusal.errorDescription);
	}
	return errorEnvelope(refusal.error, refusal.errorDescription);
}
