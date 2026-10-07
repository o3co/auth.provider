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
 * The exchange's email gate under `oauth.requireEmailVerified`, the gate every
 * path that mints for a user applies. With the setting on, the user behind the
 * subject — the `sub` the issued token names — is read through
 * `userRepository.findBySubject`: a user the Store does not hold, or whose
 * email is not verified (core's `isEmailVerified`), is `invalid_request`, and a
 * read that throws is a 503. No subject is exempt: a subject that is a
 * client's (a `client_credentials` token's `sub`) names no user the Store
 * holds. Built with the setting on and no repository that can look a user
 * up, it throws, so the composition does not start. With the setting off,
 * nothing is read.
 */

import type { GrantDependencies, GrantHandlerResult, ProviderDeps } from "@o3co/auth-provider-core";
import {
	consoleLogger,
	isEmailVerified,
	loggableError,
	type SupportsSubjectLookup,
	supportsSubjectLookup,
} from "@o3co/auth-provider-core";
import { invalidRequest } from "./answers.mjs";

/** What the gate reads: the optional `userRepository` slot, and the logger an outage is reported on. */
export type EmailGateDependencies = Pick<GrantDependencies, "logger"> &
	ProviderDeps<never, "userRepository">;

/** The gate's answer for `subject`: the refusal, or `null` when the exchange may mint for it. */
export type EmailGate = (subject: string, clientId: string) => Promise<GrantHandlerResult | null>;

const passes: EmailGate = async () => null;

/**
 * The gate for a grant built under `requireEmailVerified`; one that reads
 * nothing when the setting is off. Throws when the setting is on and the
 * `userRepository` slot is unfilled or cannot answer `findBySubject`.
 */
export function emailGate(deps: EmailGateDependencies, requireEmailVerified: boolean): EmailGate {
	if (!requireEmailVerified) return passes;
	const userRepository = deps.userRepository;
	if (userRepository === undefined || !supportsSubjectLookup(userRepository)) {
		throw new Error(
			"The token_exchange grant: oauth.requireEmailVerified is on, and the userRepository slot " +
				"is not filled with a repository that has findBySubject, so the user behind a " +
				"subject token cannot be read. Fill the slot with a UserRepository that implements " +
				"findBySubject.",
		);
	}
	const lookup: SupportsSubjectLookup = userRepository;
	return async (subject, clientId) => {
		// The field is read inside the `try`: an accessor-backed record can reach its
		// backend on that read, and a throw there is the same outage.
		let verified: boolean;
		try {
			verified = isEmailVerified(await lookup.findBySubject(subject));
		} catch (err) {
			(deps.logger ?? consoleLogger).error(
				{ store: "user_repository", step: "read", clientId, err: loggableError(err) },
				"token_exchange_user_repository_unavailable",
			);
			return {
				result: {
					status: 503,
					error: "temporarily_unavailable",
					errorDescription: "identity resolution unavailable",
				},
			};
		}
		if (verified) return null;
		// RFC 8693 §2.2.2: a subject token unacceptable based on policy is
		// `invalid_request`, as every other token this grant refuses.
		return invalidRequest("email address is not verified");
	};
}
