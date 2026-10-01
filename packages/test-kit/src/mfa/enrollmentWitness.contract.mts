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
 * The contract suite of the MFA enrollment witness: a `UserRepository` that
 * writes it (`markMfaEnrolled`, detected by `supportsMfaEnrollmentWitness`)
 * and answers it back as `User.mfaEnrolled` on `authenticate` and on
 * `authenticateByToken` alike, read through core's `readMfaEnrollmentWitness`.
 * A federated session records the witness from the second read, so a
 * repository that answers it on the first alone fails.
 *
 * Holds a repository to: the capability detected; a user nobody marked read
 * as not enrolled, through either read; a mark resolving to nothing and the
 * next login answering it, `true` and `false` alike; after each mark,
 * `authenticateByToken` answering every user's witness as `authenticate`
 * does; a repeated mark a success that changes
 * nothing; the last of successive marks holding; a mark reaching its own
 * subject alone; concurrent marks of one value all succeeding; a mark of
 * either value for a subject the backend does not hold refused with a throw,
 * every held witness left as it was; and, when the harness can make one, an
 * outage thrown, never resolved as done. Each case builds a fresh harness
 * and closes it.
 */

import assert from "node:assert/strict";
import {
	readMfaEnrollmentWitness,
	supportsMfaEnrollmentWitness,
	type UserRepository,
} from "@o3co/auth-provider-core";
import type { ContractCase } from "@o3co/auth-provider-core/testing";

/** A user the backend holds: its subject (`User.id`) and what each read resolves to it. */
export interface MfaEnrollmentWitnessUser {
	readonly subject: string;
	/** With `password`, what `authenticate` resolves to this user. */
	readonly username: string;
	readonly password: string;
	/** A handle `authenticateByToken` resolves to this user. */
	readonly token: string;
}

/** What one case runs over: a fresh backend and the repository under test over it. */
export interface MfaEnrollmentWitnessHarness {
	/** The repository under test. */
	readonly repository: UserRepository;
	/** Two users the backend holds, neither marked. */
	readonly users: readonly [MfaEnrollmentWitnessUser, MfaEnrollmentWitnessUser];
	/** A subject the backend does not hold. */
	readonly unknownSubject: string;
	/** Puts the backend into an outage: every later mark fails. Required by the outage case. */
	readonly outage?: () => void | Promise<void>;
	/** Releases the backend once the case ends. */
	readonly close?: () => Promise<void>;
}

export interface MfaEnrollmentWitnessContractInput {
	/** Builds a fresh harness for each case. */
	readonly build: () => Promise<MfaEnrollmentWitnessHarness>;
	/** Whether the harness can make an outage (`outage`); `true` adds the outage case. */
	readonly withOutage: boolean;
}

/** The repository's `markMfaEnrolled`, which the first case holds it to having. */
function markOf(harness: MfaEnrollmentWitnessHarness) {
	const { repository } = harness;
	assert.ok(
		supportsMfaEnrollmentWitness(repository),
		"the repository does not write the witness: it has no markMfaEnrolled",
	);
	return (subject: string, enrolled: boolean) => repository.markMfaEnrolled(subject, enrolled);
}

/** What the next login of `user` answers of the witness, read as the provider reads it. */
async function witnessOf(harness: MfaEnrollmentWitnessHarness, user: MfaEnrollmentWitnessUser) {
	const answered = await harness.repository.authenticate(user.username, user.password);
	assert.ok(answered !== null, `authenticate refused ${user.username}, a user the backend holds`);
	assert.equal(
		answered.id,
		user.subject,
		`authenticate answered another user for ${user.username}`,
	);
	return readMfaEnrollmentWitness(answered);
}

/** What `authenticateByToken` answers of `user`'s witness, read as the provider reads it. */
async function witnessByTokenOf(
	harness: MfaEnrollmentWitnessHarness,
	user: MfaEnrollmentWitnessUser,
) {
	const answered = await harness.repository.authenticateByToken(user.token);
	assert.ok(
		answered !== null,
		`authenticateByToken refused the token of ${user.username}, a user the backend holds`,
	);
	assert.equal(
		answered.id,
		user.subject,
		`authenticateByToken answered another user for the token of ${user.username}`,
	);
	return readMfaEnrollmentWitness(answered);
}

/** A case that builds its harness, runs `body` over it and closes it. */
function contractCase(
	input: MfaEnrollmentWitnessContractInput,
	name: string,
	body: (harness: MfaEnrollmentWitnessHarness) => Promise<void>,
): ContractCase {
	return {
		name,
		run: async () => {
			const harness = await input.build();
			try {
				await body(harness);
			} finally {
				await harness.close?.();
			}
		},
	};
}

/** The cases of the enrollment witness's contract over the harnesses `input` builds. */
export function mfaEnrollmentWitnessContract(
	input: MfaEnrollmentWitnessContractInput,
): readonly ContractCase[] {
	const cases: ContractCase[] = [
		contractCase(
			input,
			"the repository writes the witness: supportsMfaEnrollmentWitness answers true",
			async (harness) => {
				assert.equal(supportsMfaEnrollmentWitness(harness.repository), true);
			},
		),
		contractCase(input, "a user nobody marked authenticates as not enrolled", async (harness) => {
			for (const user of harness.users) {
				assert.equal(await witnessOf(harness, user), "not_enrolled", user.username);
			}
		}),
		contractCase(
			input,
			"a user nobody marked reads as not enrolled through authenticateByToken",
			async (harness) => {
				for (const user of harness.users) {
					assert.equal(await witnessByTokenOf(harness, user), "not_enrolled", user.username);
				}
			},
		),
		contractCase(
			input,
			"marking a user enrolled resolves to nothing, and the next authenticate answers the user enrolled",
			async (harness) => {
				const [user] = harness.users;
				assert.equal(await markOf(harness)(user.subject, true), undefined);
				assert.equal(await witnessOf(harness, user), "enrolled");
			},
		),
		contractCase(
			input,
			"marking a user not enrolled after enrolled answers the user not enrolled",
			async (harness) => {
				const [user] = harness.users;
				const mark = markOf(harness);
				await mark(user.subject, true);
				assert.equal(await mark(user.subject, false), undefined);
				assert.equal(await witnessOf(harness, user), "not_enrolled");
			},
		),
		contractCase(
			input,
			"marking the value already held succeeds and keeps it, either way",
			async (harness) => {
				const [user] = harness.users;
				const mark = markOf(harness);
				await mark(user.subject, true);
				await mark(user.subject, true);
				assert.equal(await witnessOf(harness, user), "enrolled");
				await mark(user.subject, false);
				await mark(user.subject, false);
				assert.equal(await witnessOf(harness, user), "not_enrolled");
			},
		),
		contractCase(
			input,
			"after each mark, authenticateByToken answers the same witness as authenticate",
			async (harness) => {
				const [first, second] = harness.users;
				const mark = markOf(harness);
				const marks: readonly (readonly [MfaEnrollmentWitnessUser, boolean])[] = [
					[first, true],
					[second, true],
					[first, false],
					[second, false],
				];
				for (const [user, enrolled] of marks) {
					await mark(user.subject, enrolled);
					for (const read of harness.users) {
						assert.equal(
							await witnessByTokenOf(harness, read),
							await witnessOf(harness, read),
							`after marking ${user.username} ${enrolled}, the two reads of ${read.username} differ`,
						);
					}
				}
			},
		),
		contractCase(input, "the last of successive marks holds", async (harness) => {
			const [user] = harness.users;
			const mark = markOf(harness);
			for (const enrolled of [true, false, true]) await mark(user.subject, enrolled);
			assert.equal(await witnessOf(harness, user), "enrolled");
		}),
		contractCase(input, "a mark reaches its own subject alone", async (harness) => {
			const [first, second] = harness.users;
			const mark = markOf(harness);
			await mark(first.subject, true);
			assert.equal(await witnessOf(harness, second), "not_enrolled");
			await mark(second.subject, true);
			await mark(first.subject, false);
			assert.equal(await witnessOf(harness, first), "not_enrolled");
			assert.equal(await witnessOf(harness, second), "enrolled");
		}),
		contractCase(
			input,
			"concurrent marks of one value all succeed, and the value holds",
			async (harness) => {
				const [user] = harness.users;
				const mark = markOf(harness);
				await Promise.all(Array.from({ length: 5 }, () => mark(user.subject, true)));
				assert.equal(await witnessOf(harness, user), "enrolled");
			},
		),
		contractCase(
			input,
			"a mark for a subject the backend does not hold throws, whether it marks true or false, and leaves every held witness as it was",
			async (harness) => {
				const [enrolled, cleared] = harness.users;
				const mark = markOf(harness);
				await mark(enrolled.subject, true);
				await mark(cleared.subject, false);
				for (const value of [true, false]) {
					await assert.rejects(
						mark(harness.unknownSubject, value),
						`a mark of ${value} for a subject the backend does not hold resolved as done`,
					);
					assert.equal(
						await witnessOf(harness, enrolled),
						"enrolled",
						`a refused mark of ${value} changed ${enrolled.username}'s witness`,
					);
					assert.equal(
						await witnessOf(harness, cleared),
						"not_enrolled",
						`a refused mark of ${value} changed ${cleared.username}'s witness`,
					);
				}
			},
		),
	];
	if (input.withOutage) {
		cases.push(
			contractCase(
				input,
				"a mark the backend cannot take throws; it never resolves as done",
				async (harness) => {
					assert.ok(harness.outage !== undefined, "the harness makes no outage");
					const mark = markOf(harness);
					await harness.outage();
					await assert.rejects(
						mark(harness.users[0].subject, true),
						"a mark during an outage resolved as done",
					);
				},
			),
		);
	}
	return cases;
}
