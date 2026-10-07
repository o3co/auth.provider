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
 * The `mfa` session requirement: core's contract held by the real requirement
 * (`fixture: false`), what it declares, its reach (the union of the enabled
 * factors' `amrValues`, and `mfa` when one of them adds it, read from
 * `mfaFactorResolver` when asked: what boot recomputes and compares), `admit`
 * and `admitPrimary`. See ADR 2026-09-28-session-admission and ADR
 * 2026-09-25-multi-factor-authentication.
 *
 * `admit`'s table, by grade alone: the `use` baseline under `mfa.mode`, the
 * token rows, `grants_nothing` met on any live session whatever the action is
 * named, and `credential_change` held to recent MFA under either mode on a
 * session a record carries, over the subject's factor records — under
 * `required`, on top of the baseline, so it is never looser than `use`.
 */

import {
	type ActionGrade,
	ADMISSION_GRADES,
	type AdmissionAction,
	type AuditEvent,
	type AuditSink,
	admitPrimary,
	admitSession,
	cookieClaim,
	createMemoryMfaTransactionStore,
	federatedSessionAuthentication,
	type Logger,
	type MfaFactor,
	type MfaFactorRecord,
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
	type SupportsSecondFactorUpdate,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { sessionRequirementContract } from "@o3co/auth-provider-test-kit";
import { describe, expect, it, type Mock, vi } from "vitest";
import { createRecoveryCodeFactor } from "#/recovery/factor.mjs";
import { createMfaRequirement } from "#/requirement.mjs";
import { createLoginTransactions } from "#/transactions.mjs";
import { openingLifecycleStore } from "./lifecycleRecords.mjs";
import {
	FACTORS,
	FIRST_BINDING_MARK,
	factorRecord,
	factorStoreHolding,
	NOT_ENROLLED_FACTS,
	resolverOver,
	stubFactor,
	unreachableFactorStore,
} from "./requirementHarness.mjs";
import { recoverySet, suiteSealing } from "./routesHarness.mjs";

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
		/** `mfa.manage.maxAgeSeconds`; the package's default, by default. */
		readonly recentMfaMaxAgeSeconds?: number;
		readonly logger?: Logger;
		readonly auditSink?: AuditSink;
		/** `mfa.enrollment.requireEmailProof`; the package's default, by default. */
		readonly requireEmailProof?: "when-mail" | "always" | "never";
		/** Whether a mail sender is wired; none, by default. */
		readonly mailWired?: boolean;
	} = {},
): Built {
	const transactionStore = options.transactionStore ?? createMemoryMfaTransactionStore();
	const requirement = createMfaRequirement({
		// No recovery set below a floor in these suites: a floor of 0.
		recoverySetFloor: async () => 0,
		mode,
		factors: resolverOver(options.factors ?? [FACTORS.totp()]),
		factorStore: options.factorStore ?? factorStoreHolding(),
		transactions: createLoginTransactions({
			store: transactionStore,
			ttlSeconds: 600,
			now: () => NOW,
		}),
		stepUpPage: PAGE,
		recentMfaMaxAgeSeconds: options.recentMfaMaxAgeSeconds ?? 300,
		logger: options.logger ?? silentLogger(),
		auditSink: options.auditSink,
		firstBinding: {
			requireEmailProof: options.requireEmailProof ?? "when-mail",
			mailWired: options.mailWired ?? false,
		},
		emailProofRequiredAtNextBinding: (subject) =>
			transactionStore.emailProofRequiredAtNextBinding(subject),
		sessionEmailProofAt: (subject, sid, nowMs) =>
			transactionStore.sessionEmailProofAt(subject, sid, nowMs),
		firstBindingAt: (subject, nowMs) => transactionStore.firstBindingAt(subject, nowMs),
		firstBindingMark: FIRST_BINDING_MARK,
		sealing: suiteSealing(),
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

describe("what the requirement declares", () => {
	it("is named mfa, starts its step-up at the page it is given, declares mfa.step_up, and the hints enrollable and email_proof", () => {
		const { requirement } = build("required");
		expect(requirement.name).toBe("mfa");
		expect(requirement.stepUpPage).toEqual(PAGE);
		expect(requirement.remediations).toEqual(["mfa.step_up"]);
		expect(requirement.hintKeys).toEqual(["enrollable", "email_proof"]);
	});

	it("declares the second-factor authority under either mode, and registers as it", () => {
		for (const mode of ["optional", "required"] as const) {
			expect(build(mode).requirement.secondFactorAuthority, mode).toBe(true);
			expect(
				resolverForTests([build(mode).requirement], { issuer: ISSUER }).get("mfa")
					?.secondFactorAuthority,
				mode,
			).toBe(true);
		}
	});

	it("reaches the union of the enabled factors' amrValues, and mfa when one adds it", () => {
		const { requirement } = build("required", {
			factors: [FACTORS.totp(), FACTORS.webauthn(), FACTORS.email(), FACTORS.recovery()],
		});
		expect([...requirement.reach].sort()).toEqual(
			["email", "hwk", "mfa", "otp", "recovery", "swk"].sort(),
		);
	});

	it("reaches mfa only when an installed factor adds it: the email code alone reaches email", () => {
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
		const reaching = build("required", {
			factors: later,
			factorStore: factorStoreHolding(...HOLDING_TOTP),
		}).requirement;
		expect([...reaching.reach].sort()).toEqual(["mfa", "otp"]);
		later.pop();
		expect([...reaching.reach].sort()).toEqual(["mfa", "otp"]);
		expect(await reaching.admit(about(password()))).toEqual(STEP_UP);
	});

	it("reads its reach at its first verdict when nothing read it before", async () => {
		const factors: MfaFactor[] = [FACTORS.totp()];
		const { requirement } = build("required", {
			factors,
			factorStore: factorStoreHolding(...HOLDING_TOTP),
		});
		expect(await requirement.admit(about(password()))).toEqual(STEP_UP);
		factors.pop();
		expect([...requirement.reach].sort()).toEqual(["mfa", "otp"]);
	});
});

// ---------------------------------------------------------------------------
// admit: the requirement's table
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

const federated = (mfaAt?: Date): UserSession =>
	record(mfaAt === undefined ? ["fed"] : ["fed", "otp", "mfa"], {
		primary: "fed",
		federation: "google",
		upstreamAmr: undefined,
		mfaAt,
	});

/** `session` with its primary `minutes` old. */
const aged = (session: UserSession, minutes: number): UserSession => ({
	...session,
	authTime: minutesAgo(minutes),
});

/** A record written before `authentication`, whose `amr` carries no primary's marker: its primary cannot be told. */
const untold = (): UserSession => record(["hwk"], undefined);

/** A password login's record written before `authentication`: read as a password primary with no second factor. */
const preUpgradePassword = (): UserSession => record(["pwd"], undefined);

const knownNot = (primary: string, mfaAt?: Date): UserSession =>
	record(["pwd"], { primary, federation: undefined, upstreamAmr: undefined, mfaAt });

/** Actions of each grade, under names of this file's own: the requirement decides by grade alone. */
const USE: AdmissionAction = { name: "test.use", grade: "use" };
const NOTHING: AdmissionAction = { name: "test.peek", grade: "grants_nothing" };
const CHANGE: AdmissionAction = { name: "test.change", grade: "credential_change" };

/**
 * What admission hands a requirement about a record read by `carrier`: the
 * view with what the login recorded of an account that is not enrolled, a
 * second factor recordable on it, as over a store that records one.
 */
const about = (
	session: UserSession | null,
	action: AdmissionAction = USE,
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
					enrollmentFacts: NOT_ENROLLED_FACTS,
					secondFactorRecordable: true,
				},
	authentication: requirementSession(session),
	carrier,
	subject: session?.sub ?? "u-alice",
	action,
	asks: undefined,
	now: new Date(),
});

/** `input` with a view admission found no second factor can be recorded on (`secondFactorRecordable`). */
const unrecordable = (input: RequirementInput): RequirementInput => ({
	...input,
	session: input.session === null ? null : { ...input.session, secondFactorRecordable: false },
});

/** What admission hands a requirement about a refresh token: the token's own amr, whatever the record. */
const aboutToken = (
	amr: readonly string[] | undefined,
	session: UserSession | null = null,
): RequirementInput => ({
	...about(session, USE, "token"),
	authentication: requirementSessionFromAmr(amr),
});

const MET: RequirementVerdict = { outcome: "met" };
const REAUTHENTICATE: RequirementVerdict = { outcome: "reauthenticate" };
const UNMET: RequirementVerdict = { outcome: "unmet" };
const STEP_UP: RequirementVerdict = { outcome: "step_up", whenStillUnmet: "reauthenticate" };

interface AdmitRow {
	readonly row: string;
	readonly mode: "optional" | "required";
	readonly input: RequirementInput;
	readonly factors?: MfaFactor[];
	/** The factor records the store holds; none, by default. */
	readonly records?: MfaFactorRecord[];
	readonly expected: RequirementVerdict;
}

/** A TOTP factor u-alice holds: a counting factor. */
const HOLDING_TOTP: MfaFactorRecord[] = [factorRecord("u-alice")];

/** Lists a store might answer for u-alice, each with an entry that is not a record, named. */
const listsWithAnEntryNotARecord = (): [string, unknown[]][] => {
	const holeBeforeRecord: unknown[] = new Array(2);
	holeBeforeRecord[1] = factorRecord("u-alice");
	const holeAfterRecord: unknown[] = [factorRecord("u-alice")];
	holeAfterRecord.length = 2;
	const { kind: _kind, ...withoutKind } = factorRecord("u-alice");
	return [
		["one hole", new Array(1)],
		["a hole before a record", holeBeforeRecord],
		["a hole after a record", holeAfterRecord],
		["undefined", [undefined]],
		["null", [null]],
		["a string", ["totp"]],
		["a record without a kind", [withoutKind]],
		["a record whose kind is no string", [{ ...factorRecord("u-alice"), kind: 1 }]],
	];
};

describe("admit — its table of verdicts under mfa.mode", () => {
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
			input: about(null, CHANGE),
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
			row: "required · use · pwd, no mfaAt, a counting factor held to step up with → step_up, refused for the baseline when it comes back unmet",
			mode: "required",
			input: about(password()),
			records: HOLDING_TOTP,
			expected: STEP_UP,
		},
		{
			row: "required · use · pwd, no mfaAt, no counting factor held → reauthenticate: a new login binds the first one",
			mode: "required",
			input: about(password()),
			expected: REAUTHENTICATE,
		},
		{
			row: "required · use · pwd, no mfaAt, recovery codes alone held → reauthenticate: they do not count",
			mode: "required",
			input: about(password()),
			factors: [FACTORS.totp(), FACTORS.recovery()],
			records: [factorRecord("u-alice", "recovery_code")],
			expected: REAUTHENTICATE,
		},
		{
			row: "required · use · pwd, no mfaAt, a record of a kind no longer installed → step_up: it may count",
			mode: "required",
			input: about(password()),
			records: [factorRecord("u-alice", "retired-kind")],
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
			input: about(password(), USE, "code"),
			records: HOLDING_TOTP,
			expected: STEP_UP,
		},
		{
			row: "required · use · the link callback's read, a pwd session without mfaAt whose subject holds a counting factor → step_up",
			mode: "required",
			input: about(password(), USE, "link"),
			records: HOLDING_TOTP,
			expected: STEP_UP,
		},
		{
			row: "required · use · the link callback's read, a pwd session without mfaAt whose subject holds none → reauthenticate",
			mode: "required",
			input: about(password(), USE, "link"),
			expected: REAUTHENTICATE,
		},
		// required · grants_nothing: met on any live session, whatever the action is named.
		{
			row: "required · grants_nothing · pwd without mfaAt → met: the action grants nothing",
			mode: "required",
			input: about(password(), NOTHING),
			expected: MET,
		},
		{
			row: "required · grants_nothing · any live session, its primary untold included → met",
			mode: "required",
			input: about(untold(), NOTHING),
			expected: MET,
		},
		{
			row: "required · grants_nothing · a primary the baseline does not know → met",
			mode: "required",
			input: about(knownNot("magiclink"), NOTHING),
			expected: MET,
		},
		{
			row: "required · grants_nothing · no session → reauthenticate: met only over a live session",
			mode: "required",
			input: about(null, NOTHING),
			expected: REAUTHENTICATE,
		},
		{
			row: "required · grants_nothing · met under any name: an action named acme.peek",
			mode: "required",
			input: about(password(), { name: "acme.peek", grade: "grants_nothing" }),
			expected: MET,
		},
		// required · grants_nothing on a token: the token's own amr is judged, whatever the grade.
		{
			row: "required · grants_nothing · token, pwd alone → unmet: a token is judged on its own amr whatever the grade",
			mode: "required",
			input: { ...aboutToken(["pwd"]), action: NOTHING },
			expected: UNMET,
		},
		{
			row: "required · grants_nothing · token, no amr at all → reauthenticate, as the token baseline counts it",
			mode: "required",
			input: { ...aboutToken(undefined), action: NOTHING },
			expected: REAUTHENTICATE,
		},
		{
			row: "required · grants_nothing · token, pwd beside a second-factor value → met by the token baseline",
			mode: "required",
			input: { ...aboutToken(["pwd", "otp", "mfa"]), action: NOTHING },
			expected: MET,
		},
		{
			row: "required · use · an action named device.lookup graded use, a counting factor held → step_up: a name admits nothing",
			mode: "required",
			input: about(password(), { name: "device.lookup", grade: "use" }),
			records: HOLDING_TOTP,
			expected: STEP_UP,
		},
		{
			row: "required · credential_change · an action named device.deny graded credential_change, a counting factor held → step_up",
			mode: "required",
			input: about(password(), { name: "device.deny", grade: "credential_change" }),
			records: HOLDING_TOTP,
			expected: STEP_UP,
		},
		// required · use, carrier token: judged on the token's own amr.
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
	];

	it.each(rows)("$row", async ({ mode, input, factors, records, expected }) => {
		const { requirement } = build(mode, {
			...(factors === undefined ? {} : { factors }),
			factorStore: factorStoreHolding(...(records ?? [])),
		});
		expect(await requirement.admit(input)).toEqual(expected);
	});
});

describe("admit — credential_change: recent MFA on a session a record carries; under required, on top of the baseline", () => {
	interface RecentRow {
		readonly row: string;
		readonly input: RequirementInput;
		readonly records: MfaFactorRecord[];
		readonly factors?: MfaFactor[];
		readonly expected: RequirementVerdict;
		/** The answer under `required` where the baseline, asked first, answers otherwise; `expected` when absent. */
		readonly required?: RequirementVerdict;
	}
	const rows: readonly RecentRow[] = [
		// A subject who holds a counting factor: a second factor inside the window.
		{
			row: "a second factor verified inside the window → met",
			input: about(password(["pwd", "otp", "mfa"], minutesAgo(1)), CHANGE),
			records: HOLDING_TOTP,
			expected: MET,
		},
		{
			row: "an email code verified inside the window, the session's amr without mfa → step_up: recent MFA is a second factor in a session that holds mfa",
			input: about(password(["pwd", "email"], minutesAgo(1)), CHANGE),
			records: [...HOLDING_TOTP, factorRecord("u-alice", "email", "f-2")],
			factors: [FACTORS.totp(), FACTORS.email()],
			expected: STEP_UP,
		},
		{
			row: "an email code verified inside the window, the subject holding the email factor alone → step_up",
			input: about(password(["pwd", "email"], minutesAgo(1)), CHANGE),
			records: [factorRecord("u-alice", "email")],
			factors: [FACTORS.totp(), FACTORS.email()],
			expected: STEP_UP,
		},
		{
			row: "a federated session with a second factor that adds no mfa inside the window → step_up",
			input: about(
				record(["fed", "email"], {
					primary: "fed",
					federation: "google",
					upstreamAmr: undefined,
					mfaAt: minutesAgo(1),
				}),
				CHANGE,
			),
			records: [factorRecord("u-alice", "email")],
			factors: [FACTORS.totp(), FACTORS.email()],
			expected: STEP_UP,
		},
		{
			row: "an email code verified inside the window in a session that holds mfa → met",
			input: about(password(["pwd", "otp", "mfa", "email"], minutesAgo(1)), CHANGE),
			records: [...HOLDING_TOTP, factorRecord("u-alice", "email", "f-2")],
			factors: [FACTORS.totp(), FACTORS.email()],
			expected: MET,
		},
		{
			row: "a second factor verified before the window → step_up, sent to log in again when still unmet",
			input: about(password(["pwd", "otp", "mfa"], minutesAgo(24 * 60)), CHANGE),
			records: HOLDING_TOTP,
			expected: STEP_UP,
		},
		{
			row: "no second factor verified in the session → step_up, however recent the primary",
			input: about(password(), CHANGE),
			records: HOLDING_TOTP,
			expected: STEP_UP,
		},
		{
			row: "an mfaAt up to the tolerated clock skew ahead of admission's clock → met",
			input: about(password(["pwd", "otp", "mfa"], new Date(Date.now() + 60_000)), CHANGE),
			records: HOLDING_TOTP,
			expected: MET,
		},
		{
			row: "measured on admission's clock: an mfaAt a minute before now is stale a day later → step_up",
			input: {
				...about(password(["pwd", "otp", "mfa"], minutesAgo(1)), CHANGE),
				now: new Date(Date.now() + 24 * 3_600_000),
			},
			records: HOLDING_TOTP,
			expected: STEP_UP,
		},
		{
			row: "a federated session with no second factor verified → step_up: a federated primary meets the baseline, not recent MFA",
			input: about(federated(), CHANGE),
			records: HOLDING_TOTP,
			expected: STEP_UP,
		},
		{
			row: "a federated session with a second factor inside the window → met",
			input: about(federated(minutesAgo(1)), CHANGE),
			records: HOLDING_TOTP,
			expected: MET,
		},
		{
			row: "a record of a kind no longer installed counts as a counting factor → step_up",
			input: about(password(), CHANGE),
			records: [factorRecord("u-alice", "retired-kind")],
			expected: STEP_UP,
		},
		{
			row: "a code's read is judged as the cookie's",
			input: about(password(), CHANGE, "code"),
			records: HOLDING_TOTP,
			expected: STEP_UP,
		},
		{
			row: "a link's read is judged as the cookie's",
			input: about(password(), CHANGE, "link"),
			records: HOLDING_TOTP,
			expected: STEP_UP,
		},
		{
			row: "a counting factor held and no factor enabled → unmet: nothing could finish a step-up",
			input: about(password(), CHANGE),
			records: HOLDING_TOTP,
			factors: [],
			expected: UNMET,
		},
		{
			row: "a counting factor held, and a session no second factor can be recorded on → reauthenticate",
			input: unrecordable(about(password(), CHANGE)),
			records: HOLDING_TOTP,
			expected: REAUTHENTICATE,
		},
		// A subject with no counting factor: a recent primary instead.
		{
			row: "no factor record, a password primary inside the window → met; under required, a new login: nothing to step up with",
			input: about(password(), CHANGE),
			records: [],
			expected: MET,
			required: REAUTHENTICATE,
		},
		{
			row: "no factor record, a password primary before the window → reauthenticate; under required, a new login: nothing to step up with",
			input: about(aged(password(), 24 * 60), CHANGE),
			records: [],
			expected: REAUTHENTICATE,
			required: REAUTHENTICATE,
		},
		{
			row: "no factor record, a federated primary inside the window → met",
			input: about(federated(), CHANGE),
			records: [],
			expected: MET,
		},
		{
			row: "no factor record, a federated primary before the window → reauthenticate",
			input: about(aged(federated(), 24 * 60), CHANGE),
			records: [],
			expected: REAUTHENTICATE,
		},
		{
			row: "no factor record, a stale primary with a second factor verified inside the window → reauthenticate: a first binding needs a recent primary",
			input: about(aged(password(["pwd", "recovery", "mfa"], minutesAgo(1)), 24 * 60), CHANGE),
			records: [],
			expected: REAUTHENTICATE,
		},
		{
			row: "recovery codes alone do not count: a primary inside the window → met; under required, a new login: nothing to step up with",
			input: about(password(), CHANGE),
			records: [factorRecord("u-alice", "recovery_code")],
			factors: [FACTORS.totp(), FACTORS.recovery()],
			expected: MET,
			required: REAUTHENTICATE,
		},
		{
			row: "recovery codes alone do not count: a primary before the window → reauthenticate; under required, a new login: nothing to step up with",
			input: about(aged(password(), 24 * 60), CHANGE),
			records: [factorRecord("u-alice", "recovery_code")],
			factors: [FACTORS.totp(), FACTORS.recovery()],
			expected: REAUTHENTICATE,
			required: REAUTHENTICATE,
		},
		{
			row: "recovery codes alone do not count: a federated primary inside the window → met",
			input: about(federated(), CHANGE),
			records: [factorRecord("u-alice", "recovery_code")],
			factors: [FACTORS.totp(), FACTORS.recovery()],
			expected: MET,
		},
		{
			row: "another subject's factor does not count: a primary inside the window → met; under required, a new login: nothing to step up with",
			input: about(password(), CHANGE),
			records: [factorRecord("u-bob")],
			expected: MET,
			required: REAUTHENTICATE,
		},
		{
			row: "no factor record, a stale primary, and a session no second factor can be recorded on → reauthenticate: never stepped up",
			input: unrecordable(about(aged(password(), 24 * 60), CHANGE)),
			records: [],
			expected: REAUTHENTICATE,
		},
		// No session, or a primary the rule cannot judge.
		{
			row: "no session → reauthenticate",
			input: about(null, CHANGE),
			records: HOLDING_TOTP,
			expected: REAUTHENTICATE,
		},
		{
			row: "a primary that cannot be told → reauthenticate, however recent",
			input: about(untold(), CHANGE),
			records: [],
			expected: REAUTHENTICATE,
		},
		{
			row: "a primary the baseline does not know → reauthenticate, even beside a recent mfaAt",
			input: about(knownNot("magiclink", minutesAgo(1)), CHANGE),
			records: HOLDING_TOTP,
			expected: REAUTHENTICATE,
		},
	];

	for (const mode of ["optional", "required"] as const) {
		it.each(rows)(`${mode} · $row`, async ({ input, records, factors, expected, required }) => {
			const { requirement } = build(mode, {
				...(factors === undefined ? {} : { factors }),
				factorStore: factorStoreHolding(...records),
			});
			expect(await requirement.admit(input)).toEqual(
				mode === "required" ? (required ?? expected) : expected,
			);
		});
	}

	it("measures the window mfa.manage.maxAgeSeconds gives: a second factor half an hour old is recent under an hour's window, not under the default", async () => {
		const input = about(password(["pwd", "otp", "mfa"], minutesAgo(30)), CHANGE);
		const factorStore = factorStoreHolding(...HOLDING_TOTP);
		const hour = build("required", { factorStore, recentMfaMaxAgeSeconds: 3_600 }).requirement;
		const byDefault = build("required", { factorStore }).requirement;
		expect(await hour.admit(input)).toEqual(MET);
		expect(await byDefault.admit(input)).toEqual(STEP_UP);
	});
});

describe("admit — under required, credential_change is never looser than use", () => {
	const RECOVERY_ONLY = [factorRecord("u-alice", "recovery_code")];
	const WITH_RECOVERY = [FACTORS.totp(), FACTORS.recovery()];

	it("sends a password session without a second factor, signed in inside the window, whose subject holds no counting factor to log in again — as use does: the login binds its first factor", async () => {
		const { requirement } = build("required");
		expect(await requirement.admit(about(password(), CHANGE))).toEqual(REAUTHENTICATE);
		expect(await requirement.admit(about(password(), USE))).toEqual(REAUTHENTICATE);
	});

	it("sends a password session written before authentication, whose subject holds no factor, to log in again", async () => {
		const { requirement } = build("required");
		expect(await requirement.admit(about(preUpgradePassword(), CHANGE))).toEqual(REAUTHENTICATE);
		expect(await requirement.admit(about(preUpgradePassword(), USE))).toEqual(REAUTHENTICATE);
	});

	it("sends a password session without a second factor whose subject holds recovery codes alone to log in again", async () => {
		const { requirement } = build("required", {
			factors: WITH_RECOVERY,
			factorStore: factorStoreHolding(...RECOVERY_ONLY),
		});
		expect(await requirement.admit(about(password(), CHANGE))).toEqual(REAUTHENTICATE);
	});

	it("steps up a password session without a second factor whose subject holds a counting factor, as use does", async () => {
		const { requirement } = build("required", { factorStore: factorStoreHolding(...HOLDING_TOTP) });
		expect(await requirement.admit(about(password(), CHANGE))).toEqual(STEP_UP);
		expect(await requirement.admit(about(password(), USE))).toEqual(STEP_UP);
	});

	it("answers the baseline's other answers too: unmet with no factor enabled, a new login where a step-up cannot be recorded", async () => {
		expect(
			await build("required", { factors: [] }).requirement.admit(about(password(), CHANGE)),
		).toEqual(UNMET);
		expect(
			await build("required").requirement.admit(unrecordable(about(preUpgradePassword(), CHANGE))),
		).toEqual(REAUTHENTICATE);
	});

	it("meets credential_change only where it meets use, over every session and factor records these suites build", async () => {
		const sessions: Readonly<Record<string, UserSession | null>> = {
			none: null,
			pwd: password(),
			"pwd, stale": aged(password(), 24 * 60),
			"pwd written before authentication": preUpgradePassword(),
			"pwd+mfaAt": password(["pwd", "otp", "mfa"], minutesAgo(1)),
			"pwd+mfaAt, stale": password(["pwd", "otp", "mfa"], minutesAgo(24 * 60)),
			fed: federated(),
			"fed, stale": aged(federated(), 24 * 60),
			untold: untold(),
			magiclink: knownNot("magiclink", minutesAgo(1)),
		};
		const holdings: Readonly<Record<string, MfaFactorRecord[]>> = {
			nothing: [],
			totp: HOLDING_TOTP,
			"recovery codes": RECOVERY_ONLY,
		};
		for (const [held, records] of Object.entries(holdings)) {
			const { requirement } = build("required", {
				factors: WITH_RECOVERY,
				factorStore: factorStoreHolding(...records),
			});
			for (const [name, session] of Object.entries(sessions)) {
				const change = await requirement.admit(about(session, CHANGE));
				const use = await requirement.admit(about(session, USE));
				if (change.outcome === "met") expect(use, `${name}, holding ${held}`).toEqual(MET);
			}
		}
	});
});

describe("admit — credential_change on a token: judged on the token's own amr, as every grade", () => {
	it("under required: a password-only token is unmet, one with a second-factor value met however old, one with no amr sent to log in", async () => {
		const { requirement } = build("required", {
			factorStore: factorStoreHolding(...HOLDING_TOTP),
		});
		const change = (amr: readonly string[] | undefined) => ({ ...aboutToken(amr), action: CHANGE });
		expect(await requirement.admit(change(["pwd"]))).toEqual(UNMET);
		expect(await requirement.admit(change(["pwd", "otp", "mfa"]))).toEqual(MET);
		expect(await requirement.admit(change(["fed"]))).toEqual(MET);
		expect(await requirement.admit(change(undefined))).toEqual(REAUTHENTICATE);
	});

	it("under optional: met", async () => {
		const { requirement } = build("optional", {
			factorStore: factorStoreHolding(...HOLDING_TOTP),
		});
		expect(await requirement.admit({ ...aboutToken(["pwd"]), action: CHANGE })).toEqual(MET);
	});
});

describe("admit — credential_change reads the subject's factor records", () => {
	it("throws when the records cannot be listed, under either mode, even beside a recent second factor", async () => {
		for (const mode of ["optional", "required"] as const) {
			const { requirement } = build(mode, { factorStore: unreachableFactorStore() });
			await expect(requirement.admit(about(federated(), CHANGE)), mode).rejects.toThrow(
				"factor store unreachable",
			);
			await expect(
				requirement.admit(about(password(["pwd", "otp", "mfa"], minutesAgo(1)), CHANGE)),
				mode,
			).rejects.toThrow("factor store unreachable");
		}
	});

	it("throws when the store answers a list that is not one, never read as no counting factor", async () => {
		for (const answer of [null, {}, { length: 0 }, ""]) {
			const { requirement } = build("required", {
				factorStore: { ...factorStoreHolding(), list: async () => answer as never },
			});
			await expect(
				requirement.admit(about(federated(), CHANGE)),
				JSON.stringify(answer),
			).rejects.toThrow(TypeError);
		}
	});

	it("throws when the store answers a list with an entry that is not a record — a hole included — never read as fewer records", async () => {
		for (const [what, answer] of listsWithAnEntryNotARecord()) {
			for (const session of [federated(), password()]) {
				const { requirement } = build("required", {
					factorStore: { ...factorStoreHolding(), list: async () => answer as never },
				});
				await expect(requirement.admit(about(session, CHANGE)), what).rejects.toThrow(TypeError);
			}
		}
	});

	it("reads them for credential_change, and for use only where the baseline would step a password session up: otherwise use and grants_nothing are answered over a store that is down", async () => {
		const { requirement } = build("required", { factorStore: unreachableFactorStore() });
		expect(
			await requirement.admit(about(password(["pwd", "otp", "mfa"], minutesAgo(1)), USE)),
		).toEqual(MET);
		expect(await requirement.admit(about(federated(), USE))).toEqual(MET);
		expect(await requirement.admit(about(password(), NOTHING))).toEqual(MET);
		await expect(requirement.admit(about(password(), USE))).rejects.toThrow();
		const optional = build("optional", { factorStore: unreachableFactorStore() }).requirement;
		expect(await optional.admit(about(password(), USE))).toEqual(MET);
	});

	it("reads none for a session it sends to log in whatever they hold: no session, or a primary it cannot judge", async () => {
		const { requirement } = build("required", { factorStore: unreachableFactorStore() });
		expect(await requirement.admit(about(null, CHANGE))).toEqual(REAUTHENTICATE);
		expect(await requirement.admit(about(untold(), CHANGE))).toEqual(REAUTHENTICATE);
		expect(await requirement.admit(about(knownNot("magiclink"), CHANGE))).toEqual(REAUTHENTICATE);
	});

	it("reads none under required where the baseline answers without them: no factor enabled, or a session no second factor can be recorded on", async () => {
		const down = unreachableFactorStore();
		expect(
			await build("required", { factorStore: down, factors: [] }).requirement.admit(
				about(password(), CHANGE),
			),
		).toEqual(UNMET);
		expect(
			await build("required", { factorStore: down }).requirement.admit(
				unrecordable(about(preUpgradePassword(), CHANGE)),
			),
		).toEqual(REAUTHENTICATE);
	});

	it("throws under required where the baseline would step a password session up and the records cannot be read: whether a counting factor is held decides it", async () => {
		const { requirement } = build("required", { factorStore: unreachableFactorStore() });
		await expect(requirement.admit(about(password(), CHANGE))).rejects.toThrow();
		await expect(requirement.admit(about(preUpgradePassword(), USE))).rejects.toThrow();
	});

	it("reads the live record's subject's, the code's first read included, which names no subject of its own", async () => {
		const list = vi.fn(async (_subject: string) => [] as MfaFactorRecord[]);
		const { requirement } = build("required", {
			factorStore: { ...factorStoreHolding(), list },
		});
		await requirement.admit({ ...about(federated(), CHANGE, "code"), subject: undefined });
		expect(list.mock.calls).toEqual([["u-alice"]]);
	});
});

/** A store holding `session` as it is handed, with the step-up capability: its `recordSecondFactor` records nothing. */
const storeHolding = (session: UserSession): UserSessionStore & SupportsSecondFactorUpdate => ({
	kind: "test",
	create: async () => {},
	get: async (sid) => (sid === session.sid ? session : null),
	delete: async () => {},
	recordSecondFactor: async () => null,
});

describe("credential_change through admission, under each mode", () => {
	const CHANGE_ACTIONS = { "test.change": { grade: "credential_change" } } as const;
	const admitChange = (session: UserSession, requirements: SessionRequirement[]) =>
		admitSession(
			{
				userSessionStore: storeHolding(session),
				sessionLifecycleStore: openingLifecycleStore(session.sub),
				subjectRevocation: undefined,
				requirements: resolverForTests(requirements, {
					issuer: ISSUER,
					actions: CHANGE_ACTIONS,
				}),
				acrTable: readAcrTable({}),
				logger: undefined,
				auditSink: undefined,
			},
			{
				claim: cookieClaim({
					session: { isAuthenticated: true, sid: session.sid, user: { id: session.sub } },
				}),
				action: "test.change",
			},
		);
	const stale = password(["pwd", "otp", "mfa"], minutesAgo(24 * 60));
	const recent = password(["pwd", "otp", "mfa"], minutesAgo(1));

	it("off — no requirement registered: a session whose second factor is a day old is admitted", async () => {
		expect(await admitChange(stale, [])).toMatchObject({ outcome: "admitted" });
	});

	for (const mode of ["optional", "required"] as const) {
		it(`${mode}: a subject holding a counting factor is stepped up to the MFA page without recent MFA, and admitted with it`, async () => {
			const { requirement } = build(mode, { factorStore: factorStoreHolding(...HOLDING_TOTP) });
			expect(await admitChange(stale, [requirement])).toMatchObject({
				outcome: "step_up",
				requirement: "mfa",
				page: { href: `${ISSUER}/mfa` },
				whenStillUnmet: "reauthenticate",
			});
			expect(await admitChange(recent, [requirement])).toMatchObject({ outcome: "admitted" });
		});

		it(`${mode}: an outage of the factor store is unavailable, naming the requirement`, async () => {
			const { requirement } = build(mode, { factorStore: unreachableFactorStore() });
			expect(await admitChange(recent, [requirement])).toEqual({
				outcome: "unavailable",
				store: "mfa",
			});
		});
	}
});

describe("admit — decides by grade alone, over every grade core has", () => {
	/** A password session without a second factor, its subject holding a counting factor, under required, for each grade an action registers with. */
	const PASSWORD_ONLY: Readonly<Record<ActionGrade, RequirementVerdict>> = {
		use: STEP_UP,
		grants_nothing: MET,
		credential_change: STEP_UP,
	};

	it("answers each grade an action registers with", async () => {
		const { requirement } = build("required", {
			factorStore: factorStoreHolding(...HOLDING_TOTP),
		});
		for (const grade of ADMISSION_GRADES) {
			if (grade === "remediation") continue;
			expect(
				await requirement.admit(about(password(), { name: "test.action", grade })),
				grade,
			).toEqual(PASSWORD_ONLY[grade]);
		}
	});
});

describe("admit — a step-up only where admission's view says a second factor can be recorded on the session", () => {
	it("sends a password session to log in again, where the table steps it up, when its view says none can be recorded", async () => {
		const { requirement } = build("required", {
			factorStore: factorStoreHolding(...HOLDING_TOTP),
		});
		expect(await requirement.admit(about(password()))).toEqual(STEP_UP);
		expect(await requirement.admit(unrecordable(about(password())))).toEqual(REAUTHENTICATE);
		expect(await requirement.admit(unrecordable(about(password(), CHANGE)))).toEqual(
			REAUTHENTICATE,
		);
		expect(await requirement.admit(unrecordable(about(password(), USE)))).toEqual(REAUTHENTICATE);
	});

	it("reads a view without the answer as one none can be recorded on", async () => {
		const { requirement } = build("required", {
			factorStore: factorStoreHolding(...HOLDING_TOTP),
		});
		const input = about(password());
		const { secondFactorRecordable: _answer, ...without } = input.session ?? {};
		expect(
			await requirement.admit({ ...input, session: without as NonNullable<typeof input.session> }),
		).toEqual(REAUTHENTICATE);
	});

	it("changes nothing else: met stays met and unmet stays unmet, for a token too", async () => {
		const { requirement } = build("required");
		expect(
			await requirement.admit(unrecordable(about(password(["pwd", "otp", "mfa"], minutesAgo(1))))),
		).toEqual(MET);
		expect(await requirement.admit(unrecordable(about(federated())))).toEqual(MET);
		expect(await requirement.admit(unrecordable(about(password(), NOTHING)))).toEqual(MET);
		expect(await requirement.admit(aboutToken(["pwd"]))).toEqual(UNMET);
		const nothing = build("required", { factors: [] }).requirement;
		expect(await nothing.admit(unrecordable(about(password())))).toEqual(UNMET);
	});
});

describe("admit — through admission, over a store that records a step-up, a record no second factor can be recorded on", () => {
	const ACTIONS = {
		"test.use": { grade: "use" },
		"test.change": { grade: "credential_change" },
	} as const;
	const admitOver = (
		session: UserSession,
		requirement: SessionRequirement,
		action: keyof typeof ACTIONS,
	) =>
		admitSession(
			{
				userSessionStore: storeHolding(session),
				sessionLifecycleStore: openingLifecycleStore(session.sub),
				subjectRevocation: undefined,
				requirements: resolverForTests([requirement], { issuer: ISSUER, actions: ACTIONS }),
				acrTable: readAcrTable({}),
				logger: undefined,
				auditSink: undefined,
			},
			{
				claim: cookieClaim({
					session: { isAuthenticated: true, sid: session.sid, user: { id: session.sub } },
				}),
				action,
			},
		);
	/** `session` with an `amr` no type admits beside its well-formed `authentication`: a custom store's record. */
	const withAmr = (session: UserSession, amr: unknown): UserSession =>
		({ ...session, amr }) as unknown as UserSession;
	const UNRECORDABLE_AMR: Readonly<Record<string, (amr: readonly string[]) => unknown>> = {
		"an empty value": (amr) => [...amr, ""],
		"a number": (amr) => [...amr, 1],
		"a string": (amr) => amr.join(" "),
	};

	for (const [shape, amrOf] of Object.entries(UNRECORDABLE_AMR)) {
		it(`required · use: the baseline sends a password session without a second factor to log in again, never to a step-up it could not record — amr holding ${shape}`, async () => {
			const { requirement } = build("required", {
				factorStore: factorStoreHolding(...HOLDING_TOTP),
			});
			const session = withAmr(password(), amrOf(["pwd"]));
			expect(await admitOver(session, requirement, "test.use")).toMatchObject({
				outcome: "reauthenticate",
				requirement: "mfa",
			});
		});

		for (const mode of ["optional", "required"] as const) {
			it(`${mode} · credential_change: recent MFA sends a session whose second factor is a day old to log in again, never to a step-up it could not record — amr holding ${shape}`, async () => {
				const { requirement } = build(mode, {
					factorStore: factorStoreHolding(...HOLDING_TOTP),
				});
				const session = withAmr(
					password(["pwd", "otp", "mfa"], minutesAgo(24 * 60)),
					amrOf(["pwd", "otp", "mfa"]),
				);
				expect(await admitOver(session, requirement, "test.change")).toMatchObject({
					outcome: "reauthenticate",
					requirement: "mfa",
				});
			});
		}
	}

	it("steps up the same sessions whose record a second factor can be recorded on", async () => {
		const factorStore = factorStoreHolding(...HOLDING_TOTP);
		const stepUp = { outcome: "step_up", requirement: "mfa", whenStillUnmet: "reauthenticate" };
		expect(
			await admitOver(password(), build("required", { factorStore }).requirement, "test.use"),
		).toMatchObject(stepUp);
		for (const mode of ["optional", "required"] as const) {
			expect(
				await admitOver(
					password(["pwd", "otp", "mfa"], minutesAgo(24 * 60)),
					build(mode, { factorStore }).requirement,
					"test.change",
				),
				mode,
			).toMatchObject(stepUp);
		}
	});
});

// ---------------------------------------------------------------------------
// admitPrimary: decideAfterPrimary, and the interruption
// ---------------------------------------------------------------------------

describe("admitPrimary — after a password login", () => {
	it("establishes under optional when the subject holds no factor record", async () => {
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

	it("never opens a first binding while any record exists — recovery codes alone, a kind no longer installed — and interrupts for a second factor instead", async () => {
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

	it("reads a recovery set with no code left as no record: established under optional, a first binding under required", async () => {
		const exhausted = {
			...factorRecord("u-alice", "recovery_code"),
			data: suiteSealing().sealFactorData(
				{ subject: "u-alice", id: "f-1", kind: "recovery_code" },
				recoverySet(0).data,
			),
		};
		for (const mode of ["optional", "required"] as const) {
			const { requirement } = build(mode, {
				factors: [FACTORS.totp(), createRecoveryCodeFactor({ count: 2 })],
				factorStore: factorStoreHolding(exhausted),
			});
			const admission = await admitPrimary(depsFor(requirement), primaryOf("u-alice"));
			if (mode === "optional") {
				expect(admission.outcome, mode).toBe("establish");
				continue;
			}
			if (admission.outcome !== "interrupt") throw new Error("not interrupted");
			expect((await admission.open("sess-1")).body.error, mode).toBe("mfa_enrollment_required");
		}
	});

	it("still interrupts for a second factor over a recovery set with a code left, or one whose data does not open", async () => {
		const sealedFor = (subject: string, count: number) => ({
			...factorRecord("u-alice", "recovery_code"),
			data: suiteSealing().sealFactorData(
				{ subject, id: "f-1", kind: "recovery_code" },
				recoverySet(count).data,
			),
		});
		for (const [what, record] of [
			["a code left", sealedFor("u-alice", 1)],
			["data that does not open", sealedFor("u-bob", 0)],
		] as const) {
			for (const mode of ["optional", "required"] as const) {
				const { requirement } = build(mode, {
					factors: [FACTORS.totp(), createRecoveryCodeFactor({ count: 2 })],
					factorStore: factorStoreHolding(record),
				});
				const admission = await admitPrimary(depsFor(requirement), primaryOf("u-alice"));
				if (admission.outcome !== "interrupt") throw new Error(`${what}, ${mode}: not interrupted`);
				expect((await admission.open("sess-1")).body.error, `${what}, ${mode}`).toBe(
					"mfa_required",
				);
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

	/** What a first binding under `options` opens for alice, whose account carries `user`. */
	const firstBinding = async (
		options: Parameters<typeof build>[1],
		user: Record<string, unknown> = { email: "alice@example.com" },
		before?: (store: MfaTransactionStore) => Promise<void>,
	) => {
		const built = build("required", options);
		await before?.(built.transactionStore);
		const admission = await admitPrimary(depsFor(built.requirement), primaryOf("u-alice", user));
		if (admission.outcome !== "interrupt") throw new Error("not interrupted");
		const answer = await admission.open("sess-1");
		const transaction = await built.transactionStore.get(answer.body.transaction as string);
		return { hint: answer.body.hints?.email_proof, emailProof: transaction?.emailProof };
	};

	it("asks for the account-email proof first where a mail sender is wired and the account has an address: the hint says so, and the transaction requires it", async () => {
		expect(await firstBinding({ mailWired: true })).toEqual({ hint: true, emailProof: "required" });
		expect(await firstBinding({ mailWired: true, requireEmailProof: "always" })).toEqual({
			hint: true,
			emailProof: "required",
		});
	});

	it("asks for none without a sender, for an account with no address, or under never", async () => {
		const none = { hint: false, emailProof: "not_required" };
		expect(await firstBinding({ mailWired: false })).toEqual(none);
		expect(await firstBinding({ mailWired: false }, { email: "not an address" })).toEqual(none);
		for (const email of [undefined, "", null]) {
			expect(await firstBinding({ mailWired: true }, { email }), String(email)).toEqual(none);
		}
		expect(await firstBinding({ mailWired: true, requireEmailProof: "never" })).toEqual(none);
	});

	it("reads the address as the login's enrollment facts say it: one it cannot read asks for a proof nobody can give under when-mail — refused, never skipped — and changes nothing under never", async () => {
		const asked = { hint: true, emailProof: "required" };
		for (const email of ["not an address", "Alice <alice@example.com>", "a%b@example.com", 42]) {
			expect(await firstBinding({ mailWired: true }, { email }), String(email)).toEqual(asked);
		}
		const logger = silentLogger();
		expect(
			await firstBinding(
				{ mailWired: true, requireEmailProof: "never", logger },
				{ email: "Alice <alice@example.com>" },
			),
		).toEqual({ hint: false, emailProof: "not_required" });
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it("asks for it under always even where nobody can give it — no sender, no address — never skipped", async () => {
		const asked = { hint: true, emailProof: "required" };
		expect(await firstBinding({ mailWired: false, requireEmailProof: "always" })).toEqual(asked);
		expect(
			await firstBinding({ mailWired: true, requireEmailProof: "always" }, { email: undefined }),
		).toEqual(asked);
	});

	it("says at warn when the proof it asks for cannot be given — no sender, no address, or one it cannot read — naming the subject and why, never the address", async () => {
		const logger = silentLogger();
		await firstBinding({ mailWired: false, requireEmailProof: "always", logger });
		await firstBinding(
			{ mailWired: true, requireEmailProof: "always", logger },
			{ email: undefined },
		);
		await firstBinding({ mailWired: true, logger }, { email: "Alice <alice@example.com>" });
		expect(logger.warn.mock.calls).toEqual([
			[{ sub: "u-alice", reason: "no_sender" }, "mfa_email_proof_unprovable"],
			[{ sub: "u-alice", reason: "no_address" }, "mfa_email_proof_unprovable"],
			[{ sub: "u-alice", reason: "unreadable_address" }, "mfa_email_proof_unprovable"],
		]);
		expect(JSON.stringify(logger.warn.mock.calls)).not.toContain("alice@example.com");
		const quiet = silentLogger();
		await firstBinding({ mailWired: true, logger: quiet });
		await firstBinding({ mailWired: false, logger: quiet });
		expect(quiet.warn).not.toHaveBeenCalled();
	});

	it("asks for it while the operator reset's flag stands, whatever the setting (D25)", async () => {
		const flagged = (store: MfaTransactionStore) => store.requireEmailProofAtNextBinding("u-alice");
		const asked = { hint: true, emailProof: "required" };
		for (const requireEmailProof of ["when-mail", "always", "never"] as const) {
			expect(
				await firstBinding({ mailWired: true, requireEmailProof }, undefined, flagged),
				requireEmailProof,
			).toEqual(asked);
		}
		expect(
			await firstBinding({ mailWired: false, requireEmailProof: "never" }, undefined, flagged),
		).toEqual(asked);
	});

	it("throws when the flag cannot be read, or reads other than a boolean — admission answers unavailable — and opens nothing", async () => {
		for (const failing of [
			async () => {
				throw new Error("transaction store unreachable");
			},
			async () => "yes" as never,
		]) {
			const transactionStore = createMemoryMfaTransactionStore();
			const create = vi.spyOn(transactionStore, "create");
			const { requirement } = build("required", {
				transactionStore: { ...transactionStore, emailProofRequiredAtNextBinding: failing },
			});
			expect(await admitPrimary(depsFor(requirement), primaryOf("u-alice"))).toEqual({
				outcome: "unavailable",
				store: "mfa",
			});
			expect(create).not.toHaveBeenCalled();
		}
	});

	it("says nothing when a first binding offers a kind", async () => {
		const logger = silentLogger();
		const { requirement } = build("required", { logger });
		const admission = await admitPrimary(depsFor(requirement), primaryOf("u-alice"));
		if (admission.outcome !== "interrupt") throw new Error("not interrupted");
		await admission.open("sess-1");
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it("answers a subject the Store says enrolled, holding no record, as an outage under either mode: the event recorded, the cause naming the inconsistency, nothing opened", async () => {
		for (const mode of ["optional", "required"] as const) {
			const events: AuditEvent[] = [];
			const transactionStore = createMemoryMfaTransactionStore();
			const create = vi.spyOn(transactionStore, "create");
			const { requirement } = build(mode, {
				transactionStore,
				auditSink: { kind: "recording", record: async (event) => void events.push(event) },
			});
			const primary = primaryOf("u-alice", { mfaEnrolled: true });

			const thrown = await requirement.admitPrimary?.(primary).catch((err: unknown) => err);
			expect(thrown, mode).toMatchObject({
				name: "MfaEnrollmentStateInconsistentError",
				reason: "mfa_enrollment_state_inconsistent",
			});
			expect(await admitPrimary(depsFor(requirement), primary), mode).toEqual({
				outcome: "unavailable",
				store: "mfa",
			});
			expect(create, mode).not.toHaveBeenCalled();
			expect(events, mode).toEqual([
				expect.objectContaining({
					type: "mfa.enrollment_state_inconsistent",
					subject: "u-alice",
					details: { purpose: "login", witness: "enrolled" },
				}),
				expect.objectContaining({ type: "mfa.enrollment_state_inconsistent" }),
			]);
		}
	});

	it("answers a witness the Store answered malformed — null, a number, a string, an object — as the same outage, never a first binding", async () => {
		for (const mfaEnrolled of [null, 1, "true", {}]) {
			const events: AuditEvent[] = [];
			const { requirement } = build("required", {
				auditSink: { kind: "recording", record: async (event) => void events.push(event) },
			});
			await expect(
				requirement.admitPrimary?.(primaryOf("u-alice", { mfaEnrolled })),
				JSON.stringify(mfaEnrolled),
			).rejects.toMatchObject({ reason: "mfa_enrollment_state_inconsistent" });
			expect(
				events.map((event) => event.details),
				JSON.stringify(mfaEnrolled),
			).toEqual([{ purpose: "login", witness: "malformed" }]);
		}
	});

	it("compares the witness with the records that count: recovery codes alone beside it are the same outage; a counting record, or one of a kind no longer installed, is asked for", async () => {
		const enrolled = primaryOf("u-alice", { mfaEnrolled: true });
		const alone = build("required", {
			factors: [FACTORS.totp(), FACTORS.recovery()],
			factorStore: factorStoreHolding(factorRecord("u-alice", "recovery_code")),
		});
		await expect(alone.requirement.admitPrimary?.(enrolled)).rejects.toMatchObject({
			reason: "mfa_enrollment_state_inconsistent",
		});
		for (const kind of ["totp", "retired-kind"]) {
			const { requirement } = build("required", {
				factors: [FACTORS.totp(), FACTORS.recovery()],
				factorStore: factorStoreHolding(factorRecord("u-alice", kind)),
			});
			const admission = await admitPrimary(depsFor(requirement), enrolled);
			expect(admission.outcome, kind).toBe("interrupt");
			if (admission.outcome !== "interrupt") return;
			expect((await admission.open("sess-1")).body.error, kind).toBe("mfa_required");
		}
	});

	it("reads no witness while a counting record stands: a malformed one beside it is asked for the factor", async () => {
		const { requirement } = build("required", {
			factorStore: factorStoreHolding(factorRecord("u-alice", "totp")),
		});
		const admission = await admitPrimary(
			depsFor(requirement),
			primaryOf("u-alice", { mfaEnrolled: "yes" }),
		);
		expect(admission.outcome).toBe("interrupt");
		if (admission.outcome !== "interrupt") return;
		expect((await admission.open("sess-1")).body.error).toBe("mfa_required");
	});

	it("opens a first binding for a subject the Store says is not enrolled — false, or no witness at all", async () => {
		for (const user of [{ mfaEnrolled: false }, {}]) {
			const { requirement } = build("required");
			const admission = await admitPrimary(depsFor(requirement), primaryOf("u-alice", user));
			expect(admission.outcome, JSON.stringify(user)).toBe("interrupt");
			if (admission.outcome !== "interrupt") return;
			expect((await admission.open("sess-1")).body.error).toBe("mfa_enrollment_required");
		}
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

	it("throws when the store answers a list with an entry that is not a record — a hole included — admission answers unavailable, never a password-only session", async () => {
		for (const [what, answer] of listsWithAnEntryNotARecord()) {
			for (const mode of ["optional", "required"] as const) {
				const { requirement } = build(mode, {
					factorStore: { ...factorStoreHolding(), list: async () => answer as never },
				});
				await expect(requirement.admitPrimary?.(primaryOf("u-alice")), what).rejects.toThrow(
					TypeError,
				);
				expect(await admitPrimary(depsFor(requirement), primaryOf("u-alice")), what).toEqual({
					outcome: "unavailable",
					store: "mfa",
				});
			}
		}
	});

	it("reads an empty list as no factor: a first binding under required, the session under optional", async () => {
		const factorStore = { ...factorStoreHolding(), list: async () => [] };
		expect(
			await build("optional", { factorStore }).requirement.admitPrimary?.(primaryOf("u-alice")),
		).toBe("establish");
		const { requirement } = build("required", { factorStore });
		const admission = await admitPrimary(depsFor(requirement), primaryOf("u-alice"));
		expect(admission.outcome).toBe("interrupt");
		if (admission.outcome !== "interrupt") return;
		expect((await admission.open("sess-1")).body.error).toBe("mfa_enrollment_required");
	});

	it("establishes a primary that is not a password login without reading the factors: the baseline applies after pwd only", async () => {
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
