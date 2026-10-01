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
 * The `mfa` requirement over every action a bundled consumer admits, as its
 * package registers it, under both modes and each setup — the factors
 * installed, whether a step-up can be recorded, and the factor records the
 * subject holds — answers the verdict table in `bundled-actions.fixture.mts`.
 */

import {
	createMemoryMfaTransactionStore,
	type Logger,
	type RequirementInput,
	type RequirementVerdict,
	requirementSession,
	requirementSessionFromAmr,
	type UserSession,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { createMfaRequirement } from "#/requirement.mjs";
import { createLoginTransactions } from "#/transactions.mjs";
import {
	BUNDLED_ACTIONS,
	SESSION_SITUATIONS,
	SETUPS,
	TOKEN_SITUATIONS,
	VERDICTS,
} from "./bundled-actions.fixture.mjs";
import {
	FACTORS,
	factorRecord,
	factorStoreHolding,
	NO_FIRST_BINDING_MARK,
	NOT_ENROLLED_FACTS,
	resolverOver,
	SEALING,
	WITHOUT_MAIL,
} from "./requirementHarness.mjs";

const NOW = Date.parse("2026-09-30T00:00:00Z");
const minutesAgo = (minutes: number): Date => new Date(NOW - minutes * 60_000);

const silent = (): Logger => {
	const logger = {
		trace: () => {},
		debug: () => {},
		info: () => {},
		warn: () => {},
		error: () => {},
		fatal: () => {},
		child: () => logger,
	};
	return logger as unknown as Logger;
};

const record = (
	amr: readonly string[],
	authentication: UserSession["authentication"],
): UserSession => ({
	sid: "sid-1",
	sub: "u-alice",
	authTime: minutesAgo(1),
	createdAt: minutesAgo(1),
	expiresAt: new Date(NOW + 3_600_000),
	claims: {},
	amr,
	authentication,
});

const password = (amr: readonly string[] = ["pwd"], mfaAt?: Date): UserSession =>
	record(amr, { primary: "pwd", federation: undefined, upstreamAmr: undefined, mfaAt });

const SESSIONS: Readonly<Record<(typeof SESSION_SITUATIONS)[number], UserSession | null>> = {
	none: null,
	pwd: password(),
	"pwd+mfaAt": password(["pwd", "otp", "mfa"], minutesAgo(1)),
	fed: record(["fed"], {
		primary: "fed",
		federation: "google",
		upstreamAmr: undefined,
		mfaAt: undefined,
	}),
	untold: record(["hwk"], undefined),
	"unknown primary": record(["pwd"], {
		primary: "magiclink",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: minutesAgo(1),
	}),
	"pwd, stale": { ...password(), authTime: minutesAgo(24 * 60) },
};

const CODE: Readonly<Record<RequirementVerdict["outcome"], string>> = {
	met: "m",
	reauthenticate: "r",
	step_up: "s",
	unmet: "u",
};

/** A verdict as one letter; a step-up that is not sent to log in again when still unmet is marked. */
const letter = (verdict: RequirementVerdict): string =>
	CODE[verdict.outcome] +
	(verdict.outcome === "step_up" && verdict.whenStillUnmet !== "reauthenticate" ? "?" : "");

/** What admission hands the requirement for the action, in each situation of its carrier. */
function inputsFor(name: string): RequirementInput[] {
	const { grade, carrier } = BUNDLED_ACTIONS[name] as (typeof BUNDLED_ACTIONS)[string];
	const action = { name, grade };
	const at = { asks: undefined, now: new Date(NOW), subject: "u-alice", action, carrier };
	if (carrier === "token") {
		return TOKEN_SITUATIONS.map((amr) => ({
			...at,
			session: null,
			authentication: requirementSessionFromAmr(amr),
		}));
	}
	return SESSION_SITUATIONS.map((situation) => {
		const session = SESSIONS[situation];
		return {
			...at,
			session:
				session === null
					? null
					: {
							sid: session.sid,
							sub: session.sub,
							authTime: session.authTime,
							expiresAt: session.expiresAt,
							enrollmentFacts: NOT_ENROLLED_FACTS,
						},
			authentication: requirementSession(session),
		};
	});
}

describe("the mfa requirement over every bundled action, by the grade its package registers", () => {
	for (const mode of ["optional", "required"] as const) {
		for (const [setup, { factors, stepUpRecordable, holds }] of Object.entries(SETUPS)) {
			const table = VERDICTS[`${mode} · ${setup}`] as Readonly<Record<string, string>>;

			it(`answers the table's verdicts — ${mode}, ${setup}`, async () => {
				const requirement = createMfaRequirement({
					mode,
					factors: resolverOver(factors.map(() => FACTORS.totp())),
					factorStore: factorStoreHolding(
						...(holds as readonly string[]).map((kind) => factorRecord("u-alice", kind)),
					),
					transactions: createLoginTransactions({
						store: createMemoryMfaTransactionStore(),
						ttlSeconds: 600,
						now: () => NOW,
					}),
					stepUpPage: { url: "/mfa", params: {} },
					stepUpRecordable,
					recentMfaMaxAgeSeconds: 300,
					logger: silent(),
					...WITHOUT_MAIL,
					...NO_FIRST_BINDING_MARK,
					sealing: SEALING,
				});
				const answered: Record<string, string> = {};
				for (const name of Object.keys(BUNDLED_ACTIONS)) {
					let letters = "";
					for (const input of inputsFor(name)) letters += letter(await requirement.admit(input));
					answered[name] = letters;
				}
				expect(answered).toEqual(table);
			});
		}
	}
});
