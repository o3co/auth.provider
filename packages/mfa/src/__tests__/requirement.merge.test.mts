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
 * The session-admission ADR's acceptance criterion 4, against the real
 * requirement: the MFA ADR's step-4 table — its D16 and D17 rows, as
 * `decideMfaRequirement` decided them — passes unchanged against core's
 * merge (`admitSession`, D2 step 7) with the `mfa` requirement this package
 * registers, under the mapping D2 states (`mergeAdmission`).
 *
 * The rows are core's, one list: `MERGE_ROW_GROUPS` on
 * `@o3co/auth-provider-core/testing`, which core's own merge test runs
 * against a stand-in written to D6's table. What the rule was handed as
 * `secondFactorMethods` is here the factors a composition enables, each
 * declaring its `amrValues` (TOTP, WebAuthn, the email code, recovery
 * codes); the reach is the requirement's own, read from them. Under
 * `mfa.mode = "off"` the MFA module refuses to boot, so no requirement named
 * `mfa` is registered: those rows run against admission with none, which is
 * what a composition without MFA is.
 */

import {
	ADMISSION_ACTIONS,
	type Admission,
	type AdmissionDeps,
	admitSession,
	consoleLogger,
	cookieClaim,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactor,
	type SessionRequirement,
	type StepUpPage,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	MERGE_ACR_TABLE,
	MERGE_ROW_GROUPS,
	type MergeFactors,
	type MergeRow,
	mergeAdmission,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { createMfaRequirement } from "#/requirement.mjs";
import { createLoginTransactions } from "#/transactions.mjs";
import { FACTORS, resolverOver } from "./requirementHarness.mjs";

/**
 * The factors a composition enables, standing for what the rule was handed
 * as `secondFactorMethods` (core's `MERGE_REACH`): the requirement's reach is
 * read from them.
 */
const FACTOR_SETS: Readonly<Record<MergeFactors, () => MfaFactor[]>> = {
	/** TOTP, WebAuthn and recovery codes: otp, hwk, swk, recovery, and mfa. */
	installed: () => [FACTORS.totp(), FACTORS.webauthn(), FACTORS.recovery()],
	/** TOTP and recovery codes: no factor adds hwk or swk. */
	withoutWebAuthn: () => [FACTORS.totp(), FACTORS.recovery()],
	/** The email code alone, which does not add mfa (O7). */
	emailOnly: () => [FACTORS.email()],
	/** The requirement with no factor enabled: nothing can step a session up. */
	empty: () => [],
	/** No factor at all: nothing can step a session up. */
	none: () => [],
};

/** `endpoints.mfa.url` as core's reference.conf ships it. */
/** The issuer each page is registered on, as boot registers it on oauth.jwt.issuer. */
const ISSUER = "https://auth.test";
const PAGE: StepUpPage = { url: "/mfa", params: {} };
/** The page as registered: what a step_up admission carries. */
const REGISTERED_PAGE = { ...PAGE, href: `${ISSUER}/mfa` };

/** The requirement the MFA module registers under `mode`, over the factors of `factors`. */
const realRequirement = (
	mode: "optional" | "required",
	factors: MergeFactors,
): SessionRequirement =>
	createMfaRequirement({
		mode,
		factors: resolverOver(FACTOR_SETS[factors]()),
		factorStore: createMemoryMfaFactorStore(),
		transactions: createLoginTransactions({
			store: createMemoryMfaTransactionStore(),
			ttlSeconds: 600,
		}),
		stepUpPage: PAGE,
		stepUpRecordable: true,
		logger: consoleLogger,
	});

const storeOf = (session: UserSession): UserSessionStore => ({
	kind: "test",
	create: async () => {},
	get: async (sid) => (sid === session.sid ? session : null),
	delete: async () => {},
});

const claim = () =>
	cookieClaim({ session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } } });

/** What a composition registers under the row's mode: the real requirement, or — under off, which the module refuses — none. */
const deps = (row: MergeRow): AdmissionDeps => ({
	userSessionStore: row.session === null ? undefined : storeOf(row.session),
	subjectRevocation: undefined,
	requirements: resolverForTests(
		row.mode === "off" ? [] : [realRequirement(row.mode, row.factors)],
		{ issuer: ISSUER },
	),
	acrTable: MERGE_ACR_TABLE,
	logger: undefined,
	auditSink: undefined,
});

const decide = (row: MergeRow): Promise<Admission> =>
	admitSession(deps(row), {
		claim: claim(),
		action: ADMISSION_ACTIONS["oauth.authorize"],
		asks: { acrValues: row.acrValues ?? [] },
	});

for (const group of MERGE_ROW_GROUPS) {
	describe(group.title, () => {
		it.each(group.rows)("$row", async (row) => {
			expect(await decide(row)).toEqual(mergeAdmission(row.expected, row.session, REGISTERED_PAGE));
		});
	});
}
