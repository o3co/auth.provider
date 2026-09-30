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
 * The contract suite every session requirement's tests run:
 * `sessionRequirementContract(input)` answers one case per rule, each a name
 * and an async `run` that throws when the rule is broken, so a test file runs
 * them with its own runner (`it.each(cases)("$name", ({ run }) => run())`).
 * It holds a requirement to what boot registers and seals, to answering
 * verdicts for every grade admission asks about (a `step_up` only with a
 * page, an outage thrown, never `met`), to
 * never being asked over a dead session or for a declared remediation, and
 * to interruption answers that pass core's closed body.
 */

import assert from "node:assert/strict";
import { requirementSession } from "../../user-sessions/authentication.mjs";
import type { UserSession, UserSessionStore } from "../../user-sessions/types.mjs";
import { readAcrTable } from "../acr.mjs";
import { type ActionGrade, ADMISSION_GRADES } from "../actions.mjs";
import { admitPrimary, admitSession, cookieClaim } from "../admit.mjs";
import {
	isHintKey,
	issuedRemediationActions,
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
	/** Whether the requirement under test is a fixture: a fixture never declares the second-factor authority. */
	readonly fixture: boolean;
	/**
	 * The issuer its page is registered on, as boot registers it on
	 * `oauth.jwt.issuer`. When absent, an absolute page is held to its shape
	 * alone and a path page is refused, so every case fails: pass the issuer
	 * for a requirement whose page is a path.
	 */
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

/** Every grade a requirement is asked about: all but `remediation`, which admission never asks about. */
const ASKED_GRADES = ADMISSION_GRADES.filter(
	(grade): grade is ActionGrade => grade !== "remediation",
);

/** The action the suite admits with, registered on each resolver it builds. */
const CONTRACT_ACTIONS = { "contract.action": { grade: "use" } } as const;

/** The contract's cases over the requirement `input` describes. */
export function sessionRequirementContract(
	input: RequirementContractInput,
): readonly ContractCase[] {
	const { key, fixture, issuer, build, withOutage, primary } = input;
	const liveInput = (grade: ActionGrade): RequirementInput => {
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
			name: "name equals its key, and a fixture never declares the second-factor authority",
			run: async () => {
				const requirement = build();
				assert.equal(
					requirement.name,
					key,
					"a requirement's name is the key it is contributed under",
				);
				if (fixture) {
					// As registration reads it: anything but a boolean does not register.
					assert.notEqual(
						registeredRequirement(requirement, issuer).secondFactorAuthority,
						true,
						"a fixture never declares the second-factor authority: boot binds the authority to core's MFA ports",
					);
				}
			},
		},
		{
			name: "reach holds non-empty strings, no primary's marker, no second-factor value unless the requirement declares the second-factor authority, and — in this release — nothing at all unless it does; stepUpPage is set when reach is not empty, and is valid when set",
			// Registration validates the page; the seal boot runs holds the reach
			// to its rules.
			run: async () => {
				sealRegisteredReach(registeredRequirement(build(), issuer));
			},
		},
		{
			name: "remediations are the requirement's own routes — <name>.<route> — each once",
			run: async () => {
				// Registration holds the rule; a fixture that breaks it does not register.
				const { name, remediations } = registeredRequirement(build(), issuer);
				for (const remediation of remediations) {
					assert.ok(
						remediation.startsWith(`${name}.`),
						`"${remediation}" is not a route of "${name}"`,
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
						requirements: resolverForTests([requirement], {
							...(issuer === undefined ? {} : { issuer }),
							actions: CONTRACT_ACTIONS,
						}),
						acrTable: readAcrTable({}),
						logger: undefined,
						auditSink: undefined,
					},
					{ claim: claim(), action: "contract.action" },
				);
				assert.equal(admission.outcome, "not_live");
				assert.equal(requirement.calls(), 0, "admit was called about a session that is not live");
				// Not vacuous: the same requirement is asked about a live one.
				await admitSession(
					{
						userSessionStore: storeAnswering(liveSession()),
						subjectRevocation: undefined,
						requirements: resolverForTests([requirement], {
							...(issuer === undefined ? {} : { issuer }),
							actions: CONTRACT_ACTIONS,
						}),
						acrTable: readAcrTable({}),
						logger: undefined,
						auditSink: undefined,
					},
					{ claim: claim(), action: "contract.action" },
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
				// The action core issued for the route, to the object that
				// registered, not through the resolver.
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
				for (const grade of ASKED_GRADES) {
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
