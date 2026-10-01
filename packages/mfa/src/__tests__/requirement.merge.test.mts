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
 * Core's merge rows (`MERGE_ROW_GROUPS` on `@o3co/auth-provider-core/testing`)
 * against the real `mfa` requirement this package registers: each passes
 * unchanged through `admitSession`'s merge, under `mergeAdmission`'s mapping.
 * Core's own merge test runs the same rows against a stand-in. See ADR
 * 2026-09-28-session-admission, "Acceptance criteria".
 *
 * Under `mfa.mode = "off"` the MFA module refuses to boot, so no requirement
 * named `mfa` is registered: those rows run against admission with none, which
 * is what a composition without MFA is.
 */

import {
	type Admission,
	type AdmissionDeps,
	admitSession,
	consoleLogger,
	cookieClaim,
	createMemoryMfaTransactionStore,
	type MfaFactor,
	type SessionRequirement,
	type StepUpPage,
	type UserSession,
	type SupportsSecondFactorUpdate,
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
import {
	FACTORS,
	factorRecord,
	factorStoreHolding,
	NO_FIRST_BINDING_MARK,
	resolverOver,
	WITHOUT_MAIL,
} from "./requirementHarness.mjs";

/**
 * The factors a composition enables, each declaring its `amrValues`, standing
 * for core's `MERGE_REACH`: the requirement's reach is read from them.
 */
const FACTOR_SETS: Readonly<Record<MergeFactors, () => MfaFactor[]>> = {
	/** TOTP, WebAuthn and recovery codes: otp, hwk, swk, recovery, and mfa. */
	installed: () => [FACTORS.totp(), FACTORS.webauthn(), FACTORS.recovery()],
	/** TOTP and recovery codes: no factor adds hwk or swk. */
	withoutWebAuthn: () => [FACTORS.totp(), FACTORS.recovery()],
	/** The email code alone, which does not add mfa. */
	emailOnly: () => [FACTORS.email()],
	/** The requirement with no factor enabled: nothing can step a session up. */
	empty: () => [],
	/** No factor at all: nothing can step a session up. */
	none: () => [],
};

/** The issuer each page is registered on, as boot registers it on oauth.jwt.issuer. */
const ISSUER = "https://auth.test";
/** `mfa.page.url` as the package's reference.conf ships it. */
const PAGE: StepUpPage = { url: "/mfa", params: {} };

/** The requirement the MFA module registers under `mode`, over the factors of `factors`. */
const realRequirement = (
	mode: "optional" | "required",
	factors: MergeFactors,
): SessionRequirement =>
	createMfaRequirement({
		mode,
		factors: resolverOver(FACTOR_SETS[factors]()),
		// The rows' subject holds a counting factor: a session without one is sent to log in
		// before any step-up, so the rows' step-ups are a second factor's.
		factorStore: factorStoreHolding(factorRecord("user-1")),
		transactions: createLoginTransactions({
			store: createMemoryMfaTransactionStore(),
			ttlSeconds: 600,
		}),
		stepUpPage: PAGE,
		stepUpRecordable: true,
		recentMfaMaxAgeSeconds: 300,
		logger: consoleLogger,
		...WITHOUT_MAIL,
		...NO_FIRST_BINDING_MARK,
	});

const storeOf = (session: UserSession): UserSessionStore & SupportsSecondFactorUpdate => ({
	kind: "test",
	create: async () => {},
	get: async (sid) => (sid === session.sid ? session : null),
	delete: async () => {},
	// A store that can record a second factor, as the coordinator's
	// `stepUpRecordable: true` above says the composition's store can.
	recordSecondFactor: async () => null,
});

const claim = () =>
	cookieClaim({ session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } } });

/** What a composition registers under the row's mode: the real requirement, or — under off, which the module refuses — none. */
const deps = (row: MergeRow): AdmissionDeps => ({
	userSessionStore: row.session === null ? undefined : storeOf(row.session),
	subjectRevocation: undefined,
	requirements: resolverForTests(
		row.mode === "off" ? [] : [realRequirement(row.mode, row.factors)],
		{ issuer: ISSUER, actions: { "test.use": { grade: "use" } } },
	),
	acrTable: MERGE_ACR_TABLE,
	logger: undefined,
	auditSink: undefined,
});

const decide = (rowDeps: AdmissionDeps, row: MergeRow): Promise<Admission> =>
	admitSession(rowDeps, {
		claim: claim(),
		action: "test.use",
		asks: { acrValues: row.acrValues ?? [] },
	});

for (const group of MERGE_ROW_GROUPS) {
	describe(group.title, () => {
		it.each(group.rows)("$row", async (row) => {
			// The requirement the row's composition registered: under `off`, none.
			const rowDeps = deps(row);
			expect(await decide(rowDeps, row)).toEqual(
				mergeAdmission(row.expected, row.session, rowDeps.requirements.get("mfa")),
			);
		});
	});
}
