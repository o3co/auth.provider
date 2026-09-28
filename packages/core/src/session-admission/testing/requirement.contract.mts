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
 * The contract suite every session requirement's tests run (the
 * session-admission ADR's D3): `sessionRequirementContract(input)` answers
 * one case per rule, each a name and an async `run` that throws when the
 * rule is broken — so a test file runs them with its own runner
 * (`it.each(cases)("$name", ({ run }) => run())`) and nothing here depends
 * on one. What it holds a requirement to: its name is its key, and a
 * fixture is never named `mfa`; its `reach` and `stepUpPage` are what boot
 * accepts (`sealRegisteredReach`, `checkStepUpPage`); its `remediations`
 * are names, each once; its `hintKeys` are hint names; admission never
 * calls its `admit` with a dead session or for a declared remediation; its
 * `admit` answers a verdict, a `step_up` only with a page registered; an
 * outage is thrown, never answered `met`; and an interruption's answer
 * passes the body core validates, so it carries no reserved key and no
 * hint with an address. Published on `@o3co/auth-provider-core/testing`.
 */

import assert from "node:assert/strict";
import { requirementSession } from "../../user-sessions/authentication.mjs";
import type { UserSession, UserSessionStore } from "../../user-sessions/types.mjs";
import { readAcrTable } from "../acr.mjs";
import { admitPrimary, admitSession, cookieClaim } from "../admit.mjs";
import {
	ADMISSION_ACTIONS,
	checkStepUpPage,
	isHintKey,
	issuedRemediationActions,
	MFA_REQUIREMENT_NAME,
	type PrimaryAuthentication,
	type RequirementInput,
	registeredRequirement,
	type SessionRequirement,
	sealRegisteredReach,
} from "../requirement.mjs";
import { resolverForTests } from "./resolver.mjs";

/** One rule of the contract: its name, and a run that throws when the requirement breaks it. */
export interface ContractCase {
	readonly name: string;
	readonly run: () => Promise<void>;
}

export interface RequirementContractInput {
	/** The key the requirement is contributed under. */
	readonly key: string;
	/** Whether the requirement under test is a fixture: a fixture is never named `mfa`. */
	readonly fixture: boolean;
	/** The issuer its page is held to; the page's shape alone when absent. */
	readonly issuer?: string;
	/** A fresh requirement for each case, so no case sees another's state. */
	readonly build: () => SessionRequirement;
	/** The requirement built over a dependency that is down: its `admit` must throw. Absent when it has none. */
	readonly withOutage?: () => SessionRequirement;
	/** A primary its `admitPrimary` may interrupt (built by `passwordPrimary`). Absent when it never interrupts a login. */
	readonly primary?: PrimaryAuthentication;
}

const NOW = () => new Date();

/** A live password session, the shape every requirement is asked about. */
const liveSession = (): UserSession => ({
	sid: "contract-sid",
	sub: "contract-subject",
	authTime: new Date(Date.now() - 60_000),
	createdAt: new Date(Date.now() - 60_000),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: {},
	amr: ["pwd"],
	authentication: {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	},
});

const storeAnswering = (answer: UserSession | null): UserSessionStore => ({
	kind: "contract",
	create: async () => {},
	get: async () => answer,
	delete: async () => {},
});

const claim = () =>
	cookieClaim({
		session: { isAuthenticated: true, sid: "contract-sid", user: { id: "contract-subject" } },
	});

/** A requirement whose `admit` counts its calls, delegating to `requirement`'s. */
const counting = (
	requirement: SessionRequirement,
): SessionRequirement & { calls: () => number } => {
	let calls = 0;
	return {
		...requirement,
		admit: async (input) => {
			calls++;
			return requirement.admit(input);
		},
		calls: () => calls,
	};
};

const VERDICTS: ReadonlySet<string> = new Set(["met", "reauthenticate", "step_up", "unmet"]);

/** The cases of D3's contract over the requirement `input` describes. */
export function sessionRequirementContract(
	input: RequirementContractInput,
): readonly ContractCase[] {
	const { key, fixture, issuer, build, withOutage, primary } = input;
	const liveInput = (grade: "use" | "credential_change"): RequirementInput => {
		const session = liveSession();
		return {
			session: {
				sid: session.sid,
				sub: session.sub,
				authTime: session.authTime,
				expiresAt: session.expiresAt,
			},
			authentication: requirementSession(session),
			carrier: "cookie",
			subject: session.sub,
			action: { name: "contract.action", grade },
			asks: undefined,
			now: NOW(),
		};
	};
	const cases: ContractCase[] = [
		{
			name: "name equals its key, and a fixture is never named mfa",
			run: async () => {
				const requirement = build();
				assert.equal(
					requirement.name,
					key,
					"a requirement's name is the key it is contributed under",
				);
				if (fixture) {
					assert.notEqual(
						requirement.name,
						MFA_REQUIREMENT_NAME,
						`a fixture is never named "${MFA_REQUIREMENT_NAME}": the name is reserved to the MFA requirement`,
					);
				}
			},
		},
		{
			name: "reach holds non-empty strings, no primary's marker, and no reserved value unless the name is mfa; stepUpPage is set when reach is not empty, and is valid when set",
			run: async () => {
				const registered = registeredRequirement(build(), issuer);
				sealRegisteredReach(registered);
				if (registered.stepUpPage !== undefined) checkStepUpPage(registered.stepUpPage, issuer);
			},
		},
		{
			name: "reach is empty unless the name is mfa: in this release only the MFA requirement adds vouched values to a session",
			run: async () => {
				const registered = registeredRequirement(build(), issuer);
				const reach = sealRegisteredReach(registered);
				if (registered.name !== MFA_REQUIREMENT_NAME) {
					assert.equal(
						reach.size,
						0,
						`"${registered.name}" reaches ${[...reach].join(", ")}: only the requirement named "${MFA_REQUIREMENT_NAME}" adds vouched values to a session in this release`,
					);
				}
			},
		},
		{
			name: "remediations are the requirement's own routes — <name>.<route> — each once, none a consumer's action in ADMISSION_ACTIONS",
			run: async () => {
				// Registration holds the rule; a fixture that breaks it does not register.
				const { name, remediations } = registeredRequirement(build(), issuer);
				for (const remediation of remediations) {
					assert.ok(
						remediation.startsWith(`${name}.`),
						`"${remediation}" is not a route of "${name}"`,
					);
					assert.ok(
						!Object.hasOwn(ADMISSION_ACTIONS, remediation),
						`"${remediation}" is a consumer's action: registered as a remediation it would skip every requirement for it`,
					);
				}
				assert.equal(
					new Set(remediations).size,
					remediations.length,
					"a remediation is declared once",
				);
			},
		},
		{
			name: "hintKeys are hint names",
			run: async () => {
				const { hintKeys } = registeredRequirement(build(), issuer);
				for (const hintKey of hintKeys) {
					assert.ok(isHintKey(hintKey), `"${hintKey}" is not a hint name core admits`);
				}
			},
		},
		{
			name: "admit is never called with a dead session",
			run: async () => {
				const requirement = counting(build());
				const admission = await admitSession(
					{
						userSessionStore: storeAnswering(null),
						subjectRevocation: undefined,
						requirements: resolverForTests([requirement], issuer === undefined ? {} : { issuer }),
						acrTable: readAcrTable({}),
						logger: undefined,
						auditSink: undefined,
					},
					{ claim: claim(), action: { name: "contract.action", grade: "use" } },
				);
				assert.equal(admission.outcome, "not_live");
				assert.equal(requirement.calls(), 0, "admit was called about a session that is not live");
				// Not vacuous: the same requirement is asked about a live one.
				await admitSession(
					{
						userSessionStore: storeAnswering(liveSession()),
						subjectRevocation: undefined,
						requirements: resolverForTests([requirement], issuer === undefined ? {} : { issuer }),
						acrTable: readAcrTable({}),
						logger: undefined,
						auditSink: undefined,
					},
					{ claim: claim(), action: { name: "contract.action", grade: "use" } },
				);
				assert.equal(requirement.calls(), 1, "admit was not asked about a live session");
			},
		},
		{
			name: "admit is never called for a remediation action",
			run: async () => {
				const requirement = counting(build());
				const [remediation] = requirement.remediations;
				if (remediation === undefined) return;
				const requirements = resolverForTests(
					[requirement],
					issuer === undefined ? {} : { issuer },
				);
				// The action core issued for the route (D4), to the object that
				// registered — the module's own — not through the resolver: a
				// literal would be normalised to credential_change and asked.
				const issued =
					issuedRemediationActions(requirement)?.[remediation.slice(requirement.name.length + 1)];
				assert.ok(issued !== undefined, `core issued no action for "${remediation}"`);
				const admission = await admitSession(
					{
						userSessionStore: storeAnswering(liveSession()),
						subjectRevocation: undefined,
						requirements,
						acrTable: readAcrTable({}),
						logger: undefined,
						auditSink: undefined,
					},
					{ claim: claim(), action: issued },
				);
				assert.equal(admission.outcome, "admitted");
				assert.equal(
					requirement.calls(),
					0,
					"admit was called for the requirement's own remediation",
				);
			},
		},
		{
			name: "admit answers a verdict, and a step_up only when stepUpPage is set",
			run: async () => {
				for (const grade of ["use", "credential_change"] as const) {
					const requirement = build();
					const verdict: unknown = await requirement.admit(liveInput(grade));
					assert.ok(
						typeof verdict === "object" &&
							verdict !== null &&
							VERDICTS.has(String((verdict as { outcome?: unknown }).outcome)),
						`admit answered something that is not a verdict for the ${grade} grade`,
					);
					const { outcome, whenStillUnmet } = verdict as {
						outcome: string;
						whenStillUnmet?: unknown;
					};
					if (outcome === "step_up") {
						assert.ok(
							whenStillUnmet === "reauthenticate" || whenStillUnmet === "unmet",
							"a step_up says what a session that comes back still unmet is refused for",
						);
						assert.notEqual(
							requirement.stepUpPage,
							undefined,
							"a step_up is answered only by a requirement that registered where the step-up starts",
						);
					}
				}
			},
		},
	];
	if (withOutage !== undefined) {
		cases.push({
			name: "an outage is thrown, never answered met",
			run: async () => {
				await assert.rejects(
					withOutage().admit(liveInput("use")),
					"a requirement over a dependency that is down must throw, never answer",
				);
			},
		});
	}
	if (primary !== undefined) {
		cases.push({
			name: "an interruption's body carries none of the reserved keys, and no hint value carries an address",
			run: async () => {
				const requirement = build();
				// A primary handed to a fixture that never interrupts makes this
				// case vacuous: said so, rather than passed.
				assert.ok(
					requirement.admitPrimary !== undefined,
					"a primary was handed in, but the fixture has no admitPrimary: leave `primary` out for a requirement that never interrupts a login",
				);
				const admission = await admitPrimary(
					{
						userSessionStore: undefined,
						subjectRevocation: undefined,
						requirements: resolverForTests([requirement], issuer === undefined ? {} : { issuer }),
						acrTable: readAcrTable({}),
						logger: undefined,
						auditSink: undefined,
					},
					primary,
				);
				// A primary the fixture establishes for makes this case vacuous:
				// said so, rather than passed.
				assert.ok(
					admission.outcome === "interrupt",
					`the fixture's admitPrimary answered ${admission.outcome} for the primary given, so its interruption cannot be checked: hand in a primary it interrupts, or leave \`primary\` out`,
				);
				// Core's validation of the answer is what holds the body to its
				// closed shape and the hints to the grammar: a body that fails is
				// refused here.
				const answer = await admission.open("contract-express-session");
				assert.equal(answer.status, 403);
			},
		});
	}
	return cases;
}
