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
 * A code is judged on how its session had authenticated when `/authorize`
 * admitted it — the code's `authentication` (`primary`, `mfaAt`) and its
 * `amr` — not on the live record, which a step-up may have moved since. What
 * a step-up never changes (`federation`, `upstreamAmr`, `upstreamAuthTime`)
 * is read from the live record, while its primary is the code's. A code whose
 * session is read and which carries no readable `authentication`, or whose
 * primary is not the record's, is refused. And the admitted answer's
 * `codeFields`: what a code minted on that admission records.
 */

import { describe, expect, it } from "vitest";
import { readAcrTable } from "#/session-admission/acr.mjs";
import {
	admitSession,
	type CodeCarrier,
	codeClaimFirstRead,
	codeClaimRevalidation,
	cookieClaim,
	tokenClaim,
} from "#/session-admission/admit.mjs";
import type {
	AdmissionDeps,
	RequirementInput,
	RequirementSession,
	SessionClaim,
	SessionRequirement,
} from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";
import { authenticationFreshness } from "#/user-sessions/authentication.mjs";
import type { UserSession, UserSessionStore } from "#/user-sessions/types.mjs";
import { TEST_ACTIONS } from "./actions.fixture.mjs";
import { openedLifecycleStore } from "./lifecycle.fixture.mjs";

const NOW = new Date("2026-10-06T12:00:00Z");
const minutesAgo = (minutes: number): Date => new Date(NOW.getTime() - minutes * 60_000);
const MFA_AT = minutesAgo(1);

const session = (over: Partial<UserSession> = {}): UserSession => ({
	sid: "sid-1",
	sub: "user-1",
	authTime: minutesAgo(5),
	createdAt: minutesAgo(5),
	expiresAt: new Date(NOW.getTime() + 3_600_000),
	claims: {},
	amr: ["pwd"],
	authentication: {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	},
	...over,
});

/** The record after a step-up: the password session with a second factor. */
const steppedUp = (): UserSession =>
	session({
		amr: ["pwd", "otp", "mfa"],
		authentication: {
			primary: "pwd",
			federation: undefined,
			upstreamAmr: undefined,
			mfaAt: MFA_AT,
		},
	});

/** A federated record, stepped up, whose upstream showed no authentication time. */
const federatedSteppedUp = (): UserSession =>
	session({
		amr: ["fed", "otp", "mfa"],
		authentication: {
			primary: "fed",
			federation: "acme",
			upstreamAmr: ["hwk"],
			mfaAt: MFA_AT,
			upstreamAuthTime: null,
		},
	});

const holding = (record: UserSession): UserSessionStore => ({
	kind: "test",
	create: async () => {},
	get: async (sid) => (sid === record.sid ? record : null),
	delete: async () => {},
});

/** A requirement that records what it is asked, and answers `answer` to it. */
const watching = (
	answer: (input: RequirementInput) => "met" | "unmet" = () => "met",
): { readonly requirement: SessionRequirement; readonly seen: RequirementInput[] } => {
	const seen: RequirementInput[] = [];
	return {
		seen,
		requirement: {
			name: "watch",
			reach: new Set(),
			stepUpPage: undefined,
			remediations: [],
			hintKeys: [],
			admit: async (input) => {
				seen.push(input);
				return { outcome: answer(input) };
			},
		},
	};
};

const deps = (
	record: UserSession | undefined,
	requirements: SessionRequirement[] = [],
): AdmissionDeps => ({
	userSessionStore: record === undefined ? undefined : holding(record),
	sessionLifecycleStore:
		record === undefined ? undefined : openedLifecycleStore([record.sid, record.sub]),
	subjectRevocation: undefined,
	requirements: resolverForTests(requirements, { actions: TEST_ACTIONS }),
	acrTable: readAcrTable({}),
	logger: undefined,
	auditSink: undefined,
	now: () => NOW,
});

/**
 * A code record as a repository answers it, as far as the claim builders
 * read it: `CodeCarrier` names `sid` alone, and the builders read the rest
 * by `CodeData`'s field names.
 */
const record = (fields: {
	readonly sid?: string;
	readonly amr?: unknown;
	readonly authentication?: unknown;
}): CodeCarrier => fields;

/** What `/authorize` recorded on a code minted from a password session before its step-up. */
const passwordCode = record({
	sid: "sid-1",
	amr: ["pwd"],
	authentication: { primary: "pwd", mfaAt: undefined },
});

const judgedOn = async (
	record: UserSession,
	claim: SessionClaim,
): Promise<RequirementSession | null> => {
	const { requirement, seen } = watching();
	await admitSession(deps(record, [requirement]), { claim, action: "test.use" });
	expect(seen).toHaveLength(1);
	return seen[0]?.authentication ?? null;
};

describe("a code is judged on how its session had authenticated at /authorize", () => {
	it("hands the requirements the code's primary, mfaAt and amr, not the record a step-up moved since — on both reads", async () => {
		const expected = {
			authentication: {
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
			amr: ["pwd"],
		};
		expect(await judgedOn(steppedUp(), codeClaimFirstRead(passwordCode))).toEqual(expected);
		expect(await judgedOn(steppedUp(), codeClaimRevalidation(passwordCode, "user-1"))).toEqual(
			expected,
		);
	});

	it("is refused by a requirement that holds the exchange to a second factor the code was minted without, though the session has one now", async () => {
		const { requirement } = watching((input) =>
			input.authentication?.authentication?.mfaAt === undefined ? "unmet" : "met",
		);
		expect(
			await admitSession(deps(steppedUp(), [requirement]), {
				claim: codeClaimFirstRead(passwordCode),
				action: "test.use",
			}),
		).toEqual({ outcome: "unmet", requirement: "watch", session: steppedUp() });
		// A code minted after the step-up carries it, and is admitted.
		expect(
			await admitSession(deps(steppedUp(), [requirement]), {
				claim: codeClaimFirstRead(
					record({
						sid: "sid-1",
						amr: ["pwd", "otp", "mfa"],
						authentication: { primary: "pwd", mfaAt: MFA_AT },
					}),
				),
				action: "test.use",
			}),
		).toMatchObject({ outcome: "admitted" });
	});

	it("reads what a step-up never changes — the federation, the upstream amr and the upstream authentication time — from the live record while its primary is the code's", async () => {
		expect(
			await judgedOn(
				federatedSteppedUp(),
				codeClaimFirstRead(
					record({
						sid: "sid-1",
						amr: ["fed"],
						authentication: { primary: "fed", mfaAt: undefined },
					}),
				),
			),
		).toEqual({
			authentication: {
				primary: "fed",
				federation: "acme",
				upstreamAmr: ["hwk"],
				mfaAt: undefined,
				upstreamAuthTime: null,
			},
			amr: ["fed"],
		});
	});

	it("cannot tell the primary when the code recorded none, as /authorize could not", async () => {
		expect(
			await judgedOn(
				steppedUp(),
				codeClaimFirstRead(
					record({
						sid: "sid-1",
						amr: ["pwd"],
						authentication: { primary: undefined, mfaAt: undefined },
					}),
				),
			),
		).toEqual({ authentication: undefined, amr: ["pwd"] });
	});

	it("refuses, asking no requirement, a code whose primary is not the live record's, or over a record whose authentication cannot be read", async () => {
		const cases: readonly [string, UserSession, CodeCarrier][] = [
			["a password code over a federated record", federatedSteppedUp(), passwordCode],
			[
				"a federated code over a password record",
				steppedUp(),
				record({
					sid: "sid-1",
					amr: ["fed"],
					authentication: { primary: "fed", mfaAt: undefined },
				}),
			],
			[
				"a password code over a record whose authentication cannot be read",
				session({ authentication: { primary: "" } as never }),
				passwordCode,
			],
		];
		for (const [label, live, code] of cases) {
			const { requirement, seen } = watching();
			for (const claim of [codeClaimFirstRead(code), codeClaimRevalidation(code, "user-1")]) {
				expect(
					await admitSession(deps(live, [requirement]), { claim, action: "test.use" }),
					label,
				).toEqual({ outcome: "unauthenticated" });
			}
			expect(seen, label).toEqual([]);
		}
	});

	it("never reads a session the upstream left never fresh as fresh because the code names another primary", async () => {
		// A requirement that holds the exchange to a fresh authentication: a
		// federated record whose upstream showed no time is never fresh.
		const { requirement } = watching((input) =>
			input.session !== null &&
			authenticationFreshness(input.session.authTime, input.authentication?.authentication) !==
				undefined
				? "met"
				: "unmet",
		);
		const fed = record({
			sid: "sid-1",
			amr: ["fed"],
			authentication: { primary: "fed", mfaAt: undefined },
		});
		expect(
			await admitSession(deps(federatedSteppedUp(), [requirement]), {
				claim: codeClaimFirstRead(fed),
				action: "test.use",
			}),
		).toEqual({ outcome: "unmet", requirement: "watch", session: federatedSteppedUp() });
		expect(
			await admitSession(deps(federatedSteppedUp(), [requirement]), {
				claim: codeClaimFirstRead(passwordCode),
				action: "test.use",
			}),
		).toEqual({ outcome: "unauthenticated" });
	});

	it("reads an amr the code carries in no admissible shape as vouching for nothing", async () => {
		for (const amr of [undefined, [], "pwd", [""], [1]]) {
			expect(
				await judgedOn(
					steppedUp(),
					codeClaimFirstRead(
						record({
							sid: "sid-1",
							amr,
							authentication: { primary: "pwd", mfaAt: undefined },
						}),
					),
				),
				JSON.stringify(amr),
			).toMatchObject({ amr: [] });
		}
	});

	it("hands each requirement a copy of its own: what one does to its mfaAt reaches neither the next nor the code", async () => {
		const mfaAt = new Date(MFA_AT.getTime());
		const authentication = { primary: "pwd", mfaAt };
		const code = record({ sid: "sid-1", amr: ["pwd", "otp", "mfa"], authentication });
		const first = watching();
		const second = watching();
		const claim = codeClaimFirstRead(code);
		mfaAt.setTime(0);
		const firstRequirement = {
			...first.requirement,
			admit: async (input: RequirementInput) => {
				input.authentication?.authentication?.mfaAt?.setTime(1);
				return first.requirement.admit(input);
			},
		};
		await admitSession(
			deps(steppedUp(), [firstRequirement, { ...second.requirement, name: "second" }]),
			{ claim, action: "test.use" },
		);
		expect(second.seen[0]?.authentication?.authentication?.mfaAt).toEqual(MFA_AT);
		// The claim read the code once, when it was built.
		expect(authentication.mfaAt.getTime()).toBe(0);
	});

	it("selects an acr from what the code carries, not from the record a step-up moved since", async () => {
		const asks = { acrValues: ["urn:example:mfa"] };
		const withTable = (requirements: SessionRequirement[] = []): AdmissionDeps => ({
			...deps(steppedUp(), requirements),
			acrTable: readAcrTable({ "urn:example:mfa": ["mfa"] }),
		});
		expect(
			await admitSession(withTable(), {
				claim: codeClaimFirstRead(passwordCode),
				action: "test.use",
				asks,
			}),
		).toEqual({ outcome: "unmet", requirement: "acr", session: steppedUp() });
		expect(
			await admitSession(withTable(), {
				claim: codeClaimFirstRead(
					record({
						sid: "sid-1",
						amr: ["pwd", "otp", "mfa"],
						authentication: { primary: "pwd", mfaAt: MFA_AT },
					}),
				),
				action: "test.use",
				asks,
			}),
		).toMatchObject({
			outcome: "admitted",
			acr: "urn:example:mfa",
			codeFields: { amr: ["pwd", "otp", "mfa"] },
		});
	});

	it("leaves the claim's shape as it was: what the code carries is not a field of the claim", () => {
		expect(Object.keys(codeClaimFirstRead(passwordCode)).sort()).toEqual([
			"authenticated",
			"carrier",
			"sid",
			"subject",
		]);
	});
});

describe("a code that carries no readable authentication is refused once its session is read", () => {
	const unreadable: unknown[] = [
		undefined,
		null,
		"pwd",
		[],
		{ primary: "" },
		{ primary: 7 },
		{ primary: "pwd", mfaAt: "2026-10-06T11:59:00Z" },
		{ primary: "pwd", mfaAt: new Date(Number.NaN) },
		{ primary: "pwd", mfaAt: new Date(-1) },
		// Both keys are recorded, an undefined one included: a snapshot that
		// leaves one out is not one /authorize recorded.
		{},
		{ mfaAt: undefined },
		{ primary: undefined },
		{ primary: "pwd" },
		new Date("2026-10-06T11:59:00Z"),
		// Only a plain object's own keys are a snapshot.
		Object.create({ primary: undefined, mfaAt: undefined }),
		Object.assign(new Date("2026-10-06T11:59:00Z"), { primary: undefined, mfaAt: undefined }),
		Object.assign(Object.create(null), { primary: "pwd" }),
	];

	it("as unauthenticated, on both reads, before any requirement is asked — one an earlier release issued included", async () => {
		const codes = [
			...unreadable.map((authentication) => record({ sid: "sid-1", amr: ["pwd"], authentication })),
			record({ sid: "sid-1", amr: ["pwd"] }),
			record({ sid: "sid-1" }),
		];
		for (const code of codes) {
			const { requirement, seen } = watching();
			for (const claim of [codeClaimFirstRead(code), codeClaimRevalidation(code, "user-1")]) {
				expect(
					await admitSession(deps(steppedUp(), [requirement]), { claim, action: "test.use" }),
					JSON.stringify(code),
				).toEqual({ outcome: "unauthenticated" });
			}
			expect(seen, JSON.stringify(code)).toEqual([]);
		}
	});

	it("reads a snapshot that is a plain object without a prototype, both keys its own", async () => {
		const authentication = Object.assign(Object.create(null), { primary: "pwd", mfaAt: undefined });
		expect(
			await judgedOn(
				steppedUp(),
				codeClaimFirstRead(record({ sid: "sid-1", amr: ["pwd"], authentication })),
			),
		).toMatchObject({ authentication: { primary: "pwd", mfaAt: undefined }, amr: ["pwd"] });
	});

	it("is read as before without a session store: there is no session to judge it against, and the requirements decide", async () => {
		const { requirement, seen } = watching();
		expect(
			await admitSession(deps(undefined, [requirement]), {
				claim: codeClaimFirstRead(record({})),
				action: "test.use",
			}),
		).toMatchObject({ outcome: "admitted", session: null });
		expect(seen).toHaveLength(1);
		expect(seen[0]?.authentication).toBeNull();
	});
});

describe("the code's primary is held to the record on the last reading too", () => {
	/** A store whose record changes after its first read: what a store in flux answers. */
	const changing = (first: UserSession, then: UserSession): UserSessionStore => {
		let reads = 0;
		return {
			kind: "test",
			create: async () => {},
			get: async (sid) => (sid === first.sid ? (reads++ === 0 ? first : then) : null),
			delete: async () => {},
		};
	};

	it("refuses as unauthenticated a code whose primary the record no longer holds, or whose record can no longer be read, once the requirements were asked", async () => {
		const laters: readonly [string, UserSession][] = [
			["federated", federatedSteppedUp()],
			["unreadable", session({ authentication: { primary: "" } as never })],
		];
		for (const [label, later] of laters) {
			const { requirement, seen } = watching();
			for (const claim of [
				codeClaimFirstRead(passwordCode),
				codeClaimRevalidation(passwordCode, "user-1"),
			]) {
				expect(
					await admitSession(
						{
							...deps(steppedUp(), [requirement]),
							userSessionStore: changing(steppedUp(), later),
						},
						{ claim, action: "test.use" },
					),
					label,
				).toEqual({ outcome: "unauthenticated" });
			}
			expect(seen.length, label).toBe(2);
		}
	});

	it("admits a code whose record holds its primary on both readings", async () => {
		const { requirement } = watching();
		expect(
			await admitSession(
				{
					...deps(steppedUp(), [requirement]),
					userSessionStore: changing(steppedUp(), steppedUp()),
				},
				{ claim: codeClaimFirstRead(passwordCode), action: "test.use" },
			),
		).toMatchObject({ outcome: "admitted" });
	});
});

describe("the admitted answer's codeFields: what a code minted on it records", () => {
	const admitted = async (
		record: UserSession | undefined,
		claim: SessionClaim,
	): Promise<Record<string, unknown>> => {
		const answer = await admitSession(deps(record), { claim, action: "test.use" });
		expect(answer.outcome).toBe("admitted");
		return answer as unknown as Record<string, unknown>;
	};
	const cookie = (): SessionClaim =>
		cookieClaim({ session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } } });

	it("over a cookie: what the record vouches for and how it was established, its second factor included", async () => {
		expect((await admitted(steppedUp(), cookie())).codeFields).toEqual({
			amr: ["pwd", "otp", "mfa"],
			authentication: { primary: "pwd", mfaAt: MFA_AT },
		});
	});

	it("over a record whose authentication cannot be read: nothing vouched for, and no primary — never left out", async () => {
		expect(
			(await admitted(session({ authentication: { primary: "" } as never }), cookie())).codeFields,
		).toEqual({ amr: [], authentication: { primary: undefined, mfaAt: undefined } });
	});

	it("without a session store: nothing", async () => {
		expect((await admitted(undefined, cookie())).codeFields).toEqual({
			amr: undefined,
			authentication: undefined,
		});
	});

	it("over a token, and over a code: what each carries", async () => {
		expect(
			(await admitted(steppedUp(), tokenClaim({ sid: "sid-1", sub: "user-1", amr: ["fed"] })))
				.codeFields,
		).toEqual({ amr: ["fed"], authentication: { primary: "fed", mfaAt: undefined } });
		expect((await admitted(steppedUp(), codeClaimFirstRead(passwordCode))).codeFields).toEqual({
			amr: ["pwd"],
			authentication: { primary: "pwd", mfaAt: undefined },
		});
	});

	it("is a frozen copy of its own: changing it reaches neither the record nor the next answer", async () => {
		const record = steppedUp();
		const first = (await admitted(record, cookie())).codeFields as {
			amr: string[];
			authentication: { mfaAt: Date };
		};
		expect(Object.isFrozen(first)).toBe(true);
		expect(Object.isFrozen(first.amr)).toBe(true);
		expect(Object.isFrozen(first.authentication)).toBe(true);
		first.authentication.mfaAt.setTime(0);
		expect(record.authentication?.mfaAt).toEqual(MFA_AT);
		expect((await admitted(record, cookie())).codeFields).toMatchObject({
			authentication: { mfaAt: MFA_AT },
		});
	});
});
