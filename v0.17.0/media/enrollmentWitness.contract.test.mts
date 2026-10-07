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
 * over `HttpUserRepository` and the test kit's fake Store: the witness
 * written through `markMfaEnrolled` and read back through `authenticate` and
 * `authenticateByToken`, each user resolvable by a token the fake holds for
 * it. The repository writes the witness only with `markMfaEnrolledUrl`.
 */

import { supportsMfaEnrollmentWitness } from "@o3co/auth-provider-core";
import {
	type MfaEnrollmentWitnessHarness,
	mfaEnrollmentWitnessContract,
	startFakeStore,
} from "@o3co/auth-provider-test-kit";
import { describe, expect, it } from "vitest";
import { HttpUserRepository } from "#/index.mjs";

const TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const USERS = [
	{
		subject: "user-1",
		username: "alice@example.com",
		password: "alice-password",
		token: "github:alice",
	},
	{ subject: "user-2", username: "bob@example.com", password: "bob-password", token: "github:bob" },
] as const;

async function build(): Promise<MfaEnrollmentWitnessHarness> {
	const fake = await startFakeStore({
		bearerToken: TOKEN,
		users: USERS.map((user) => ({
			id: user.subject,
			username: user.username,
			password: user.password,
			tokens: [user.token],
		})),
	});
	return {
		repository: new HttpUserRepository({
			authenticateUrl: fake.urls.authenticateUrl,
			authenticateByTokenUrl: fake.urls.authenticateByTokenUrl,
			markMfaEnrolledUrl: fake.urls.markMfaEnrolledUrl,
			bearerToken: TOKEN,
			timeout: 5000,
		}),
		users: USERS,
		unknownSubject: "nobody",
		outage: () => fake.answer("markMfaEnrolled", () => ({ status: 503 })),
		close: () => fake.close(),
	};
}

describe("the witness's write side", () => {
	it("is HttpUserRepository's own with markMfaEnrolledUrl, and absent without it", () => {
		const options = {
			authenticateUrl: "https://store.example/authenticate",
			authenticateByTokenUrl: "https://store.example/authenticate-by-token",
			timeout: 5000,
		};
		expect(
			supportsMfaEnrollmentWitness(
				new HttpUserRepository({
					...options,
					markMfaEnrolledUrl: "https://store.example/mfa/enrolled",
				}),
			),
		).toBe(true);
		expect(supportsMfaEnrollmentWitness(new HttpUserRepository(options))).toBe(false);
	});
});

describe("the enrollment witness through HttpUserRepository over the fake Store", () => {
	for (const contractCase of mfaEnrollmentWitnessContract({ build, withOutage: true })) {
		it(contractCase.name, contractCase.run);
	}
});
