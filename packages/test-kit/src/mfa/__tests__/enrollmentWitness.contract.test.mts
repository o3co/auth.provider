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
 * The enrollment witness's contract suite, run over an in-process repository
 * that keeps it, and over the fake Store through a repository that posts both
 * reads and the mark as the wire contract says. Each broken repository below
 * is refused by the case that describes what it breaks, so the suite is not
 * vacuous.
 */

import type { User, UserRepository } from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";
import {
	type ContractCase,
	type MfaEnrollmentWitnessHarness,
	mfaEnrollmentWitnessContract,
	startFakeStore,
} from "#/index.mjs";

const UNKNOWN_SUBJECT_CASE =
	"a mark for a subject the backend does not hold throws, whether it marks true or false, and leaves every held witness as it was";
const UNMARKED_BY_TOKEN_CASE =
	"a user nobody marked reads as not enrolled through authenticateByToken";
const BOTH_READS_CASE =
	"after each mark, authenticateByToken answers the same witness as authenticate";

const USERS = [
	{ subject: "user-1", username: "alice", password: "alice-password", token: "github:alice" },
	{ subject: "user-2", username: "bob", password: "bob-password", token: "github:bob" },
] as const;

type Mark = (witness: Map<string, unknown>, subject: string, enrolled: boolean) => Promise<void>;

const markHonestly: Mark = async (witness, subject, enrolled) => {
	if (!USERS.some((user) => user.subject === subject)) throw new Error("no such subject");
	witness.set(subject, enrolled);
};

/** What `authenticateByToken` answers in place of the `User` `authenticate` would answer. */
type ByToken = (answer: User) => User | null;

/**
 * An in-process repository over a map, whose mark is `mark`, whose
 * `authenticateByToken` answers `byToken` of the user a token names, and
 * which may be put into an outage.
 */
function inProcess(
	mark: Mark = markHonestly,
	byToken: ByToken = (answer) => answer,
): MfaEnrollmentWitnessHarness {
	const witness = new Map<string, unknown>();
	let down = false;
	const answerOf = (user: (typeof USERS)[number]): User => {
		const answer: User = { id: user.subject, username: user.username };
		// As a Store answers it: whatever the mark wrote, a broken one's text included.
		return witness.has(user.subject)
			? ({ ...answer, mfaEnrolled: witness.get(user.subject) } as User)
			: answer;
	};
	const repository: UserRepository = {
		authenticate: async (username, password) => {
			const user = USERS.find((u) => u.username === username && u.password === password);
			return user === undefined ? null : answerOf(user);
		},
		authenticateByToken: async (token) => {
			const user = USERS.find((u) => u.token === token);
			return user === undefined ? null : byToken(answerOf(user));
		},
		markMfaEnrolled: async (subject, enrolled) => {
			if (down) throw new Error("outage");
			await mark(witness, subject, enrolled);
		},
	};
	return {
		repository,
		users: USERS,
		unknownSubject: "nobody",
		outage: () => {
			down = true;
		},
	};
}

describe("mfaEnrollmentWitnessContract over an in-process repository", () => {
	for (const contractCase of mfaEnrollmentWitnessContract({
		build: async () => inProcess(),
		withOutage: true,
	})) {
		it(contractCase.name, contractCase.run);
	}
});

describe("mfaEnrollmentWitnessContract over the fake Store", () => {
	for (const contractCase of mfaEnrollmentWitnessContract({
		build: async () => {
			const fake = await startFakeStore({
				users: USERS.map((user) => ({
					id: user.subject,
					username: user.username,
					password: user.password,
					tokens: [user.token],
				})),
			});
			const post = (url: string, body: unknown) =>
				fetch(url, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify(body),
					redirect: "manual",
				});
			const repository: UserRepository = {
				authenticate: async (email, password) => {
					const response = await post(fake.urls.authenticateUrl, { email, password });
					return response.status === 200 ? ((await response.json()) as User) : null;
				},
				authenticateByToken: async (token) => {
					const response = await post(fake.urls.authenticateByTokenUrl, { token });
					return response.status === 200 ? ((await response.json()) as User) : null;
				},
				markMfaEnrolled: async (subject, enrolled) => {
					const response = await post(fake.urls.markMfaEnrolledUrl, { subject, enrolled });
					await response.body?.cancel();
					if (response.status !== 204) throw new Error(`HTTP ${response.status}`);
				},
			};
			return {
				repository,
				users: USERS,
				unknownSubject: "nobody",
				outage: () => fake.answer("markMfaEnrolled", () => ({ status: 503 })),
				close: () => fake.close(),
			};
		},
		withOutage: true,
	})) {
		it(contractCase.name, contractCase.run);
	}
});

/** The names of the cases that refuse the repository `harness` builds. */
async function refusedBy(build: () => MfaEnrollmentWitnessHarness): Promise<string[]> {
	const refused: string[] = [];
	for (const contractCase of mfaEnrollmentWitnessContract({
		build: async () => build(),
		withOutage: true,
	})) {
		try {
			await contractCase.run();
		} catch {
			refused.push(contractCase.name);
		}
	}
	return refused;
}

describe("the suite refuses a repository that breaks the contract", () => {
	it("one without the capability", async () => {
		const refused = await refusedBy(() => {
			const { markMfaEnrolled: _mark, ...rest } = inProcess().repository;
			return { ...inProcess(), repository: rest };
		});
		expect(refused).toContain(
			"the repository writes the witness: supportsMfaEnrollmentWitness answers true",
		);
	});

	it("one whose mark writes nothing", async () => {
		const refused = await refusedBy(() => inProcess(async () => {}));
		expect(refused).toContain(
			"marking a user enrolled resolves to nothing, and the next authenticate answers the user enrolled",
		);
	});

	it("one that writes the witness as text", async () => {
		const refused = await refusedBy(() =>
			inProcess(async (witness, subject, enrolled) => {
				witness.set(subject, String(enrolled));
			}),
		);
		expect(refused).toContain(
			"marking a user enrolled resolves to nothing, and the next authenticate answers the user enrolled",
		);
	});

	it("one that marks every subject", async () => {
		const refused = await refusedBy(() =>
			inProcess(async (witness, _subject, enrolled) => {
				for (const user of USERS) witness.set(user.subject, enrolled);
			}),
		);
		expect(refused).toContain("a mark reaches its own subject alone");
	});

	it("one that takes a mark for a subject it does not hold", async () => {
		const refused = await refusedBy(() =>
			inProcess(async (witness, subject, enrolled) => {
				witness.set(subject, enrolled);
			}),
		);
		expect(refused).toContain(UNKNOWN_SUBJECT_CASE);
	});

	it("one that erases every witness when it refuses a subject it does not hold", async () => {
		const refused = await refusedBy(() =>
			inProcess(async (witness, subject, enrolled) => {
				if (!USERS.some((user) => user.subject === subject)) {
					witness.clear();
					throw new Error("no such subject");
				}
				witness.set(subject, enrolled);
			}),
		);
		expect(refused).toContain(UNKNOWN_SUBJECT_CASE);
	});

	it("one that marks every subject enrolled when it refuses a subject it does not hold", async () => {
		const refused = await refusedBy(() =>
			inProcess(async (witness, subject, enrolled) => {
				if (!USERS.some((user) => user.subject === subject)) {
					for (const user of USERS) witness.set(user.subject, true);
					throw new Error("no such subject");
				}
				witness.set(subject, enrolled);
			}),
		);
		expect(refused).toContain(UNKNOWN_SUBJECT_CASE);
	});

	it("one that ignores a clearing mark", async () => {
		const refused = await refusedBy(() =>
			inProcess(async (witness, subject, enrolled) => {
				if (!USERS.some((user) => user.subject === subject)) throw new Error("no such subject");
				if (enrolled) witness.set(subject, true);
			}),
		);
		expect(refused).toContain(
			"marking a user not enrolled after enrolled answers the user not enrolled",
		);
	});

	it("one that answers the witness on authenticate alone", async () => {
		const refused = await refusedBy(() =>
			inProcess(markHonestly, ({ mfaEnrolled: _witness, ...answer }) => answer as User),
		);
		expect(refused).toContain(BOTH_READS_CASE);
		expect(refused).not.toContain(UNMARKED_BY_TOKEN_CASE);
	});

	it("one whose authenticateByToken answers the witness as text", async () => {
		const refused = await refusedBy(() =>
			inProcess(markHonestly, (answer) =>
				"mfaEnrolled" in answer
					? ({ ...answer, mfaEnrolled: String(answer.mfaEnrolled) } as unknown as User)
					: answer,
			),
		);
		expect(refused).toContain(BOTH_READS_CASE);
	});

	it("one whose authenticateByToken resolves no token", async () => {
		const refused = await refusedBy(() => inProcess(markHonestly, () => null));
		expect(refused).toContain(UNMARKED_BY_TOKEN_CASE);
		expect(refused).toContain(BOTH_READS_CASE);
	});

	it("one whose authenticateByToken answers another user", async () => {
		const refused = await refusedBy(() =>
			inProcess(markHonestly, (answer) => ({
				...answer,
				id: answer.id === USERS[0].subject ? USERS[1].subject : USERS[0].subject,
			})),
		);
		expect(refused).toContain(UNMARKED_BY_TOKEN_CASE);
		expect(refused).toContain(BOTH_READS_CASE);
	});

	it("one that swallows an outage", async () => {
		const refused = await refusedBy(() => ({
			...inProcess(),
			outage: () => {},
		}));
		expect(refused).toContain("a mark the backend cannot take throws; it never resolves as done");
	});
});

describe("the suite's cases", () => {
	it("include the outage case only when the harness can make one", () => {
		const names = (withOutage: boolean) =>
			mfaEnrollmentWitnessContract({ build: async () => inProcess(), withOutage }).map(
				(contractCase) => contractCase.name,
			);
		expect(names(true)).toContain(
			"a mark the backend cannot take throws; it never resolves as done",
		);
		expect(names(false)).not.toContain(
			"a mark the backend cannot take throws; it never resolves as done",
		);
		expect(names(true).length).toBe(names(false).length + 1);
	});

	it("are the kit's ContractCase: a name, and a run that answers a promise", () => {
		expectTypeOf<ContractCase>().toEqualTypeOf<{
			readonly name: string;
			readonly run: () => Promise<void>;
		}>();
		expectTypeOf(
			mfaEnrollmentWitnessContract({ build: async () => inProcess(), withOutage: false }),
		).toEqualTypeOf<readonly ContractCase[]>();
		expect(true).toBe(true);
	});
});
