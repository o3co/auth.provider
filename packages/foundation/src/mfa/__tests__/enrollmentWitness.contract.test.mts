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
 * The enrollment witness's contract suite (`@o3co/auth-provider-test-kit`)
 * over the test kit's fake Store, as far as it runs without the Store
 * adapter's `markMfaEnrolled`: the witness is read back through
 * `HttpUserRepository.authenticate`, and written by a stand-in that posts
 * the mark as the wire contract says and reads an answer other than `204`
 * through `mfaStoreStatusError`. The adapter's own `markMfaEnrolled` takes
 * the stand-in's place.
 */

import type { MfaStoreMarkEnrolledRequest, UserRepository } from "@o3co/auth-provider-core";
import {
	type MfaEnrollmentWitnessHarness,
	mfaEnrollmentWitnessContract,
	startFakeStore,
} from "@o3co/auth-provider-test-kit";
import { describe, it } from "vitest";
import { HttpUserRepository } from "#/index.mjs";
import { mfaStoreStatusError } from "#/mfa/storeFailure.mjs";

const USERS = [
	{ subject: "user-1", username: "alice@example.com", password: "alice-password" },
	{ subject: "user-2", username: "bob@example.com", password: "bob-password" },
] as const;

async function build(): Promise<MfaEnrollmentWitnessHarness> {
	const fake = await startFakeStore({
		users: USERS.map((user) => ({
			id: user.subject,
			username: user.username,
			password: user.password,
		})),
	});
	const reader = new HttpUserRepository({
		authenticateUrl: fake.urls.authenticateUrl,
		authenticateByTokenUrl: fake.urls.authenticateByTokenUrl,
		timeout: 5000,
	});
	const repository: UserRepository = {
		authenticate: (username, password) => reader.authenticate(username, password),
		authenticateByToken: (token) => reader.authenticateByToken(token),
		markMfaEnrolled: async (subject, enrolled) => {
			const body: MfaStoreMarkEnrolledRequest = { subject, enrolled };
			const response = await fetch(fake.urls.markMfaEnrolledUrl, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
				redirect: "manual",
			});
			if (response.status !== 204) {
				throw mfaStoreStatusError("markMfaEnrolled", fake.urls.markMfaEnrolledUrl, response);
			}
			await response.body?.cancel();
		},
	};
	return {
		repository,
		users: USERS,
		unknownSubject: "nobody",
		outage: () => fake.answer("markMfaEnrolled", () => ({ status: 503 })),
		close: () => fake.close(),
	};
}

describe("the enrollment witness over the fake Store, read back through HttpUserRepository", () => {
	for (const contractCase of mfaEnrollmentWitnessContract({ build, withOutage: true })) {
		it(contractCase.name, contractCase.run);
	}
});
