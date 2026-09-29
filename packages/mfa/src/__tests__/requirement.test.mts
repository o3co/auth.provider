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
 * The `mfa` session requirement (the session-admission ADR's D3, D5, D6, D7;
 * the MFA ADR's F1, F3, D13, D16, O3, and the step-8 owner decisions 1–3):
 *
 * - it holds core's contract as the real requirement (`fixture: false`);
 * - its `reach` is the union of the enabled factors' `amrValues`, and `mfa`
 *   when one of them adds it, read from `mfaFactorResolver` when asked — what
 *   boot recomputes and compares; its page is the one it is given
 *   (`endpoints.mfa.url`), its one remediation `mfa.step_up`, its hints
 *   `enrollable` and `email_proof`;
 * - `admit` is D6's table: the `use` baseline under `mfa.mode`, O3's three
 *   token rows, `device.lookup` / `device.deny` met on any live session —
 *   and `credential_change` held to the baseline until steps 12 and 14 add
 *   recent MFA (owner decision 1);
 * - `admitPrimary` reads the subject's factors after a password login: zero
 *   records under `optional` establish; zero under `required` interrupt for a
 *   first binding in its final shape, with no witness read (owner decision
 *   2); any record — a counting factor, recovery codes alone, a kind no
 *   longer installed — interrupts for a second factor, never a first
 *   binding (F3); a `list` that cannot answer is thrown, which admission
 *   answers `unavailable`.
 */

import {
	ADMISSION_ACTIONS,
	type AdmissionAction,
	admitPrimary,
	createMemoryMfaTransactionStore,
	federatedSessionAuthentication,
	type Logger,
	type MfaFactor,
	type MfaFactorStore,
	type MfaTransactionStore,
	type PrimaryAuthentication,
	passwordPrimary,
	type RequirementInput,
	type RequirementVerdict,
	readAcrTable,
	requirementSession,
	requirementSessionFromAmr,
	type SessionClaim,
	type SessionRequirement,
	type UserSession,
} from "@o3co/auth-provider-core";
import { resolverForTests, sessionRequirementContract } from "@o3co/auth-provider-core/testing";
import { describe, expect, it, type Mock, vi } from "vitest";
import { createMfaRequirement } from "#/requirement.mjs";
import { createLoginTransactions } from "#/transactions.mjs";
import {
	FACTORS,
	factorRecord,
	factorStoreHolding,
	resolverOver,
	stubFactor,
	unreachableFactorStore,
} from "./requirementHarness.mjs";

const ISSUER = "https://auth.example";

/** A logger whose `warn` is a spy and every other level does nothing. */
function silentLogger(): Logger & { readonly warn: Mock } {
	const logger = {
		trace: () => {},
		debug: () => {},
		info: () => {},
		warn: vi.fn(),
		error: () => {},
		fatal: () => {},
		child: () => logger,
	};
	return logger as unknown as Logger & { readonly warn: Mock };
}
const PAGE = { url: "/mfa", params: {} };
const NOW = 1_900_000_000_000;

interface Built {
	readonly requirement: SessionRequirement;
	readonly transactionStore: MfaTransactionStore;
}

function build(
	mode: "optional" | "required",
	options: {
		readonly factors?: MfaFactor[];
		readonly factorStore?: MfaFactorStore;
		readonly transactionStore?: MfaTransactionStore;
		/** Whether the session store can record a step-up (`supportsSecondFactorUpdate`); it can, by default. */
		readonly stepUpRecordable?: boolean;
		readonly logger?: Logger;
	} = {},
): Built {
	const transactionStore = options.transactionStore ?? createMemoryMfaTransactionStore();
	const requirement = createMfaRequirement({
		mode,
		factors: resolverOver(options.factors ?? [FACTORS.totp()]),
		factorStore: options.factorStore ?? factorStoreHolding(),
		transactions: createLoginTransactions({
			store: transactionStore,
			ttlSeconds: 600,
			now: () => NOW,
		}),
		stepUpPage: PAGE,
		stepUpRecordable: options.stepUpRecordable ?? true,
		logger: options.logger ?? silentLogger(),
	});
	return { requirement, transactionStore };
}

const primaryOf = (subject: string, user: Record<string, unknown> = {}): PrimaryAuthentication =>
	passwordPrimary({
		subject,
		user: { id: subject, username: subject, ...user },
		claims: {},
		authTime: new Date(NOW - 1_000),
		redirectTo: undefined,
		request: {},
	});

const depsFor = (requirement: SessionRequirement) => ({
	userSessionStore: undefined,
	subjectRevocation: undefined,
	requirements: resolverForTests([requirement], { issuer: ISSUER }),
	acrTable: readAcrTable({}),
	logger: undefined,
	auditSink: undefined,
});

// ---------------------------------------------------------------------------
// Core's contract
// ---------------------------------------------------------------------------

describe("the mfa requirement holds core's contract, as the real requirement", () => {
	for (const mode of ["optional", "required"] as const) {
		describe(`under mfa.mode = "${mode}"`, () => {
			const cases = sessionRequirementContract({
				key: "mfa",
				fixture: false,
				issuer: ISSUER,
				build: () =>
					build(mode, { factorStore: factorStoreHolding(factorRecord("u-contract")) }).requirement,
				primary: primaryOf("u-contract"),
			});
			it.each(cases)("$name", ({ run }) => run());
		});
	}
});

// ---------------------------------------------------------------------------
// What it declares
// ---------------------------------------------------------------------------

describe("what the requirement declares (D3, D6)", () => {
	it("is named mfa, starts its step-up at the page it is given, declares mfa.step_up, and the hints enrollable and email_proof", () => {
		const { requirement } = build("required");
		expect(requirement.name).toBe("mfa");
		expect(requirement.stepUpPage).toEqual(PAGE);
		expect(requirement.remediations).toEqual(["mfa.step_up"]);
		expect(requirement.hintKeys).toEqual(["enrollable", "email_proof"]);
	});

	it("reaches the union of the enabled factors' amrValues, and mfa when one adds it", () => {
		const { requirement } = build("required", {
			factors: [FACTORS.totp(), FACTORS.webauthn(), FACTORS.email(), FACTORS.recovery()],
		});
		expect([...requirement.reach].sort()).toEqual(
			["email", "hwk", "mfa", "otp", "recovery", "swk"].sort(),
		);
	});

	it("reaches mfa only when an installed factor adds it: the email code alone reaches email (O7)", () => {
		expect([...build("required", { factors: [FACTORS.email()] }).requirement.reach]).toEqual([
			"email",
		]);
	});

	it("reaches nothing while no factor is enabled", () => {
		expect(build("optional", { factors: [] }).requirement.reach.size).toBe(0);
	});

	it("reads the factors at its reach's first read, not when built: a factor registered before that read — in boot's name-keyed pass — is reached", () => {
		const factors: MfaFactor[] = [];
		const { requirement } = build("required", { factors });
		factors.push(FACTORS.totp());
		expect([...requirement.reach].sort()).toEqual(["mfa", "otp"]);
	});

	it("keeps the reach of its first read — boot's, which core seals and merges with — for its own verdicts too", async () => {
		const factors: MfaFactor[] = [];
		const { requirement } = build("required", { factors });
		expect(requirement.reach.size).toBe(0);
		// A factor that appears after that read changes neither the reach nor admit.
		factors.push(FACTORS.totp());
		expect(requirement.reach.size).toBe(0);
		expect(await requirement.admit(about(password()))).toEqual(UNMET);

		const later: MfaFactor[] = [FACTORS.totp()];
		const reaching = build("required", { factors: later }).requirement;
		expect([...reaching.reach].sort()).toEqual(["mfa", "otp"]);
		later.pop();
		expect([...reaching.reach].sort()).toEqual(["mfa", "otp"]);
		expect(await reaching.admit(about(password()))).toEqual(STEP_UP);
	});

	it("reads its reach at its first verdict when nothing read it before", async () => {
		const factors: MfaFactor[] = [FACTORS.totp()];
		const { requirement } = build("required", { factors });
		expect(await requirement.admit(about(password()))).toEqual(STEP_UP);
		factors.pop();
		expect([...requirement.reach].sort()).toEqual(["mfa", "otp"]);
	});
});

// ---------------------------------------------------------------------------
// admit: D6's table
// ---------------------------------------------------------------------------

const minutesAgo = (minutes: number): Date => new Date(Date.now() - minutes * 60_000);

const record = (
	amr: readonly string[],
	authentication: UserSession["authentication"],
): UserSession => ({
	sid: "sid-1",
	sub: "u-alice",
	authTime: minutesAgo(1),
	createdAt: minutesAgo(1),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: {},
	amr,
	authentication,
});

const password = (amr: readonly string[] = ["pwd"], mfaAt?: Date): UserSession =>
	record(amr, { primary: "pwd", federation: undefined, upstreamAmr: undefined, mfaAt });

const federated = (): UserSession =>
	record(["fed"], {
		primary: "fed",
		federation: "google",
		upstreamAmr: undefined,
		mfaAt: undefined,
	});

/** A record written before `authentication`, whose `amr` carries no primary's marker: its primary cannot be told. */
const untold = (): UserSession => record(["hwk"], undefined);

const knownNot = (primary: string, mfaAt?: Date): UserSession =>
	record(["pwd"], { primary, federation: undefined, upstreamAmr: undefined, mfaAt });

/** What admission hands a requirement about a record read by `carrier` (D2, step 5). */
const about = (
	session: UserSession | null,
	action: AdmissionAction = ADMISSION_ACTIONS["oauth.authorize"],
	carrier: SessionClaim["carrier"] = "cookie",
): RequirementInput => ({
	session:
		session === null
			? null
			: {
					sid: session.sid,
					sub: session.sub,
					authTime: session.authTime,
					expiresAt: session.expiresAt,
				},
	authentication: requirementSession(session),
	carrier,
	subject: session?.sub ?? "u-alice",
	action,
	asks: undefined,
	now: new Date(),
});

/** What admission hands a requirement about a refresh token (D2, step 5; D9): the token's own amr, whatever the record. */
const aboutToken = (
	amr: readonly string[] | undefined,
	session: UserSession | null = null,
): RequirementInput => ({
	...about(session, ADMISSION_ACTIONS["oauth.refresh"], "token"),
	authentication: requirementSessionFromAmr(amr),
});

const MET: RequirementVerdict = { outcome: "met" };
const REAUTHENTICATE: RequirementVerdict = { outcome: "reauthenticate" };
const UNMET: RequirementVerdict = { outcome: "unmet" };
const STEP_UP: RequirementVerdict = { outcome: "step_up", whenStillUnmet: "reauthenticate" };

const LINK = ADMISSION_ACTIONS["session.link"];

interface AdmitRow {
	readonly row: string;
	readonly mode: "optional" | "required";
	readonly input: RequirementInput;
	readonly factors?: MfaFactor[];
	readonly expected: RequirementVerdict;
}

describe("admit — D6's table under mfa.mode, with owner decision 1's rows", () => {
	const rows: readonly AdmitRow[] = [
		// required · use and credential_change: no session, or a primary the rule does not know.
		{
			row: "required · use · no session → reauthenticate",
			mode: "required",
			input: about(null),
			expected: REAUTHENTICATE,
		},
		{
			row: "required · credential_change · no session → reauthenticate",
			mode: "required",
			input: about(null, LINK),
			expected: REAUTHENTICATE,
		},
		{
			row: "required · use · a primary that cannot be told → reauthenticate",
			mode: "required",
			input: about(untold()),
			expected: REAUTHENTICATE,
		},
		{
			row: "required · use · a primary the baseline does not know → reauthenticate, never met, even beside an mfaAt",
			mode: "required",
			input: about(knownNot("magiclink", minutesAgo(1))),
			expected: REAUTHENTICATE,
		},
		// required · use: the baseline.
		{
			row: "required · use · pwd, no mfaAt, a factor to step up with → step_up, refused for the baseline when it comes back unmet",
			mode: "required",
			input: about(password()),
			expected: STEP_UP,
		},
		{
			row: "required · use · pwd, no mfaAt, no factor enabled → unmet: nothing could finish a step-up",
			mode: "required",
			factors: [],
			input: about(password()),
			expected: UNMET,
		},
		{
			row: "required · use · pwd with mfaAt → met",
			mode: "required",
			input: about(password(["pwd", "otp", "mfa"], minutesAgo(1))),
			expected: MET,
		},
		{
			row: "required · use · an email login meets the baseline: mfaAt is set (O7)",
			mode: "required",
			input: about(password(["pwd", "email"], minutesAgo(1))),
			expected: MET,
		},
		{
			row: "required · use · fed → met: the baseline applies after pwd only (D13)",
			mode: "required",
			input: about(federated()),
			expected: MET,
		},
		{
			row: "required · use · a code's read and a link's are judged as the cookie's",
			mode: "required",
			input: about(password(), ADMISSION_ACTIONS["oauth.code_exchange"], "code"),
			expected: STEP_UP,
		},
		{
			row: "required · use · the link callback's read, a pwd session without mfaAt → step_up",
			mode: "required",
			input: about(password(), ADMISSION_ACTIONS["session.link_callback"], "link"),
			expected: STEP_UP,
		},
		// required · use, refined by name: device.lookup and device.deny grant nothing.
		{
			row: "required · device.lookup · pwd without mfaAt → met: it grants nothing",
			mode: "required",
			input: about(password(), ADMISSION_ACTIONS["device.lookup"]),
			expected: MET,
		},
		{
			row: "required · device.deny · pwd without mfaAt → met: a phished device request is refused without a step-up",
			mode: "required",
			input: about(password(), ADMISSION_ACTIONS["device.deny"]),
			expected: MET,
		},
		{
			row: "required · device.deny · any live session, its primary untold included → met",
			mode: "required",
			input: about(untold(), ADMISSION_ACTIONS["device.deny"]),
			expected: MET,
		},
		{
			row: "required · device.approve · pwd without mfaAt → step_up: approving grants a device a token",
			mode: "required",
			input: about(password(), ADMISSION_ACTIONS["device.approve"]),
			expected: STEP_UP,
		},
		{
			row: "required · device.lookup · no session → reauthenticate: the refinement is for a live session",
			mode: "required",
			input: about(null, ADMISSION_ACTIONS["device.lookup"]),
			expected: REAUTHENTICATE,
		},
		{
			row: "required · a deployment's own action named device.lookup but graded credential_change is not refined",
			mode: "required",
			input: about(password(), { name: "device.lookup", grade: "credential_change" }),
			expected: STEP_UP,
		},
		// required · credential_change: the baseline until steps 12 and 14 (owner decision 1).
		{
			row: "required · credential_change · pwd without mfaAt → step_up: the baseline",
			mode: "required",
			input: about(password(), LINK),
			expected: STEP_UP,
		},
		{
			row: "required · credential_change · pwd with an old mfaAt → met: no recent-MFA rule before step 12",
			mode: "required",
			input: about(password(["pwd", "otp", "mfa"], minutesAgo(24 * 60)), LINK),
			expected: MET,
		},
		{
			row: "required · credential_change · fed → met",
			mode: "required",
			input: about(federated(), ADMISSION_ACTIONS["webauthn.register"]),
			expected: MET,
		},
		// required · use, carrier token (O3): judged on the token's own amr.
		{
			row: "required · token · pwd and no second-factor value → unmet: a password-only refresh token ends at its next refresh",
			mode: "required",
			input: aboutToken(["pwd"]),
			expected: UNMET,
		},
		{
			row: "required · token · no amr at all (issued before #481) → reauthenticate: unknown",
			mode: "required",
			input: aboutToken(undefined),
			expected: REAUTHENTICATE,
		},
		{
			row: "required · token · an empty amr → reauthenticate: unknown",
			mode: "required",
			input: aboutToken([]),
			expected: REAUTHENTICATE,
		},
		{
			row: "required · token · a passkey's hwk alone, no primary's marker (the WebAuthn grant, no sid) → met: a second-factor value is present",
			mode: "required",
			input: aboutToken(["hwk"]),
			expected: MET,
		},
		{
			row: "required · token · a synced passkey's swk alone → met",
			mode: "required",
			input: aboutToken(["swk"]),
			expected: MET,
		},
		{
			row: "required · token · mfa alone, which core never lets stand without a factor's own value → reauthenticate: it names no factor",
			mode: "required",
			input: aboutToken(["mfa"]),
			expected: REAUTHENTICATE,
		},
		{
			row: "required · token · pwd beside mfa alone → unmet: mfa names no factor",
			mode: "required",
			input: aboutToken(["pwd", "mfa"]),
			expected: UNMET,
		},
		{
			row: "required · token · an amr of values the rule does not know → reauthenticate",
			mode: "required",
			input: aboutToken(["kba"]),
			expected: REAUTHENTICATE,
		},
		{
			row: "required · token · fed → met",
			mode: "required",
			input: aboutToken(["fed"]),
			expected: MET,
		},
		{
			row: "required · token · pwd beside a second-factor value → met",
			mode: "required",
			input: aboutToken(["pwd", "otp", "mfa"]),
			expected: MET,
		},
		{
			row: "required · token · pwd beside the email code → met: a second-factor value, as the baseline counts it (O7)",
			mode: "required",
			input: aboutToken(["pwd", "email"]),
			expected: MET,
		},
		{
			row: "required · token without a live record (no sid) · judged on its amr all the same: pwd, otp, mfa → met",
			mode: "required",
			input: aboutToken(["pwd", "otp", "mfa"], null),
			expected: MET,
		},
		{
			row: "required · token without a live record · pwd alone → unmet, not reauthenticate",
			mode: "required",
			input: aboutToken(["pwd"], null),
			expected: UNMET,
		},
		{
			row: "required · token · pwd alone, over a record that stepped up later → unmet: a token is judged on what it was issued with (O3)",
			mode: "required",
			input: aboutToken(["pwd"], password(["pwd", "otp", "mfa"], minutesAgo(1))),
			expected: UNMET,
		},
		// optional: no baseline.
		{
			row: "optional · use · pwd without mfaAt → met",
			mode: "optional",
			input: about(password()),
			expected: MET,
		},
		{
			row: "optional · use · no session → met",
			mode: "optional",
			input: about(null),
			expected: MET,
		},
		{
			row: "optional · use · a primary that cannot be told → met",
			mode: "optional",
			input: about(untold()),
			expected: MET,
		},
		{
			row: "optional · token · pwd alone → met",
			mode: "optional",
			input: aboutToken(["pwd"]),
			expected: MET,
		},
		{
			row: "optional · credential_change · pwd without mfaAt → met: recent MFA is steps 12 and 14's",
			mode: "optional",
			input: about(password(), LINK),
			expected: MET,
		},
	];

	it.each(rows)("$row", async ({ mode, input, factors, expected }) => {
		const { requirement } = build(mode, factors === undefined ? {} : { factors });
		expect(await requirement.admit(input)).toEqual(expected);
	});
});

describe("admit — a step-up only where the session store can record one (the MFA ADR's F2, D20)", () => {
	it("sends a password session to log in again, where the table steps it up, when the store cannot record a second factor", async () => {
		const { requirement } = build("required", { stepUpRecordable: false });
		expect(await requirement.admit(about(password()))).toEqual(REAUTHENTICATE);
		expect(await requirement.admit(about(password(), LINK))).toEqual(REAUTHENTICATE);
		expect(await requirement.admit(about(password(), ADMISSION_ACTIONS["device.approve"]))).toEqual(
			REAUTHENTICATE,
		);
	});

	it("changes nothing else: met stays met, unmet stays unmet, a token is judged as before", async () => {
		const { requirement } = build("required", { stepUpRecordable: false });
		expect(await requirement.admit(about(password(["pwd", "otp", "mfa"], minutesAgo(1))))).toEqual(
			MET,
		);
		expect(await requirement.admit(about(federated()))).toEqual(MET);
		expect(await requirement.admit(about(password(), ADMISSION_ACTIONS["device.deny"]))).toEqual(
			MET,
		);
		expect(await requirement.admit(aboutToken(["pwd"]))).toEqual(UNMET);
		const nothing = build("required", { stepUpRecordable: false, factors: [] }).requirement;
		expect(await nothing.admit(about(password()))).toEqual(UNMET);
	});
});

// ---------------------------------------------------------------------------
// admitPrimary: decideAfterPrimary, and the interruption
// ---------------------------------------------------------------------------

describe("admitPrimary — after a password login (F1 step 1, F3; owner decision 2)", () => {
	it("establishes under optional when the subject holds no factor record: the login is as it was", async () => {
		const { requirement } = build("optional");
		expect(await requirement.admitPrimary?.(primaryOf("u-alice"))).toBe("establish");
	});

	it("reads the subject's own records: another subject's factor does not count", async () => {
		const { requirement } = build("optional", {
			factorStore: factorStoreHolding(factorRecord("u-bob")),
		});
		expect(await requirement.admitPrimary?.(primaryOf("u-alice"))).toBe("establish");
	});

	it("interrupts for a second factor when the subject holds a counting factor, under either mode", async () => {
		for (const mode of ["optional", "required"] as const) {
			const { requirement, transactionStore } = build(mode, {
				factorStore: factorStoreHolding(factorRecord("u-alice")),
			});
			const admission = await admitPrimary(depsFor(requirement), primaryOf("u-alice"));
			expect(admission.outcome, mode).toBe("interrupt");
			if (admission.outcome !== "interrupt") return;
			const answer = await admission.open("sess-regenerated");
			expect(answer, mode).toEqual({
				status: 403,
				body: { error: "mfa_required", transaction: expect.any(String), expires_in: 600 },
			});
			expect(await transactionStore.get(answer.body.transaction as string), mode).toMatchObject({
				purpose: "login",
				binding: { kind: "session", id: "sess-regenerated" },
				subject: "u-alice",
				continuation: admission.continuation,
				enrollment: "none",
			});
		}
	});

	it("never opens a first binding while any record exists — recovery codes alone, a kind no longer installed — and interrupts for a second factor instead (F3)", async () => {
		for (const mode of ["optional", "required"] as const) {
			for (const kind of ["recovery_code", "retired-kind"]) {
				const { requirement } = build(mode, {
					factorStore: factorStoreHolding(factorRecord("u-alice", kind)),
				});
				const admission = await admitPrimary(depsFor(requirement), primaryOf("u-alice"));
				expect(admission.outcome, `${mode} ${kind}`).toBe("interrupt");
				if (admission.outcome !== "interrupt") return;
				expect((await admission.open("sess-1")).body.error, `${mode} ${kind}`).toBe("mfa_required");
			}
		}
	});

	it("interrupts for a first binding under required when the subject holds no record, in its final shape: the kinds that may be enrolled and whether an email proof comes first", async () => {
		const unenrollable: MfaFactor = { ...stubFactor("email", ["email"]), enrollable: () => false };
		const { requirement, transactionStore } = build("required", {
			factors: [FACTORS.totp(), FACTORS.recovery(), unenrollable, FACTORS.webauthn()],
		});
		const admission = await admitPrimary(depsFor(requirement), primaryOf("u-alice"));
		expect(admission.outcome).toBe("interrupt");
		if (admission.outcome !== "interrupt") return;
		const answer = await admission.open("sess-regenerated");
		// Counting factors this user can enroll, in registration order: not the
		// recovery codes (they do not count), not a kind the user cannot enroll.
		expect(answer).toEqual({
			status: 403,
			body: {
				error: "mfa_enrollment_required",
				transaction: expect.any(String),
				expires_in: 600,
				hints: { enrollable: ["totp", "webauthn"], email_proof: false },
			},
		});
		expect(await transactionStore.get(answer.body.transaction as string)).toMatchObject({
			binding: { kind: "session", id: "sess-regenerated" },
			enrollment: "required",
			emailProof: "not_required",
		});
	});

	it("says so each time a first binding offers nothing — every counting factor refuses this user — naming the kinds alone, and answers as it would", async () => {
		const logger = silentLogger();
		const refusing = (kind: string): MfaFactor => ({
			...stubFactor(kind, ["email"], { addsMfa: false }),
			enrollable: () => false,
		});
		const { requirement } = build("required", {
			factors: [refusing("email"), FACTORS.recovery(), refusing("sms_code")],
			logger,
		});
		for (let login = 1; login <= 2; login++) {
			const admission = await admitPrimary(depsFor(requirement), primaryOf("u-alice"));
			if (admission.outcome !== "interrupt") throw new Error("not interrupted");
			expect((await admission.open(`sess-${login}`)).body).toMatchObject({
				error: "mfa_enrollment_required",
				hints: { enrollable: [], email_proof: false },
			});
			expect(logger.warn).toHaveBeenCalledTimes(login);
		}
		expect(logger.warn).toHaveBeenLastCalledWith(
			{ kinds: ["email", "sms_code"] },
			"mfa_enrollment_nothing_enrollable",
		);
		expect(JSON.stringify(logger.warn.mock.calls)).not.toContain("u-alice");
	});

	it("says nothing when a first binding offers a kind", async () => {
		const logger = silentLogger();
		const { requirement } = build("required", { logger });
		const admission = await admitPrimary(depsFor(requirement), primaryOf("u-alice"));
		if (admission.outcome !== "interrupt") throw new Error("not interrupted");
		await admission.open("sess-1");
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it("reads no enrollment witness before step 9: a user the Store says enrolled, with no record, is still asked for a first binding (owner decision 2)", async () => {
		const { requirement } = build("required");
		const admission = await admitPrimary(
			depsFor(requirement),
			primaryOf("u-alice", { mfaEnrolled: true }),
		);
		expect(admission.outcome).toBe("interrupt");
		if (admission.outcome !== "interrupt") return;
		expect((await admission.open("sess-1")).body.error).toBe("mfa_enrollment_required");
	});

	it("throws when the factors cannot be listed — admission answers unavailable, and nothing is opened", async () => {
		const transactionStore = createMemoryMfaTransactionStore();
		const { requirement } = build("optional", {
			factorStore: unreachableFactorStore(),
			transactionStore,
		});
		await expect(requirement.admitPrimary?.(primaryOf("u-alice"))).rejects.toThrow(
			"factor store unreachable",
		);
		expect(await admitPrimary(depsFor(requirement), primaryOf("u-alice"))).toEqual({
			outcome: "unavailable",
			store: "mfa",
		});
	});

	it("throws when the store answers a list that is not one — even one with no length, or a length of 0 — never read as no factor", async () => {
		for (const answer of [null, {}, { length: 0 }, ""]) {
			const { requirement } = build("optional", {
				factorStore: { ...factorStoreHolding(), list: async () => answer as never },
			});
			await expect(
				requirement.admitPrimary?.(primaryOf("u-alice")),
				JSON.stringify(answer),
			).rejects.toThrow(TypeError);
		}
	});

	it("establishes a primary that is not a password login without reading the factors: the baseline applies after pwd only (D13)", async () => {
		const { requirement } = build("required", { factorStore: unreachableFactorStore() });
		const federatedPrimary: PrimaryAuthentication = {
			...primaryOf("u-alice"),
			recorded: federatedSessionAuthentication({
				federation: "google",
				upstreamAmr: [],
				trusted: false,
			}),
		};
		expect(await requirement.admitPrimary?.(federatedPrimary)).toBe("establish");
	});
});
