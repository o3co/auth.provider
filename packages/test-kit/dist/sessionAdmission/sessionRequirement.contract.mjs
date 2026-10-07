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
 *
 * It reads core only through its public entries. Registration is core's
 * `resolverForTests`, which registers each requirement and seals its reach
 * as boot does: the cases that read what registration accepts register with
 * `allowAnyReach`, so a reach whose values the seal refuses fails the reach
 * case alone of them (a reach that cannot be read at all fails them too). A requirement asked directly is handed admission's view of a live
 * session built here, as admission builds it over stores that cannot record
 * a second factor.
 */
import assert from "node:assert/strict";
import { ADMISSION_GRADES, admitPrimary, admitSession, cookieClaim, createInMemorySessionLifecycleStore, issuedRemediationActions, readAcrTable, requirementSession, } from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
const NOW = () => new Date();
/** A live password session, the shape every requirement is asked about. */
const liveSession = () => ({
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
/**
 * Admission's view of `session` over stores none of which can record a
 * second factor: a frozen projection of the record, its dates copied, with
 * no enrollment facts since the record holds none.
 */
const viewOfLive = (session) => Object.freeze({
    sid: session.sid,
    sub: session.sub,
    authTime: new Date(session.authTime.getTime()),
    expiresAt: new Date(session.expiresAt.getTime()),
    secondFactorRecordable: false,
});
/**
 * `requirement` as registration answers it, its reach read but not held to
 * the seal's rules: the reach case holds it to them. Throws what registration
 * refuses.
 */
const registered = (requirement, issuer) => {
    const copy = resolverForTests([requirement], {
        ...(issuer === undefined ? {} : { issuer }),
        allowAnyReach: true,
    }).get(requirement.name);
    assert.ok(copy !== undefined, `"${requirement.name}" did not register under its name`);
    return copy;
};
const storeAnswering = (answer) => ({
    kind: "contract",
    create: async () => { },
    get: async () => answer,
    delete: async () => { },
});
/** The lifecycle store a login opened `contract-sid`'s record in: a session with no record reads as closed. */
const openedLifecycle = async () => {
    const store = createInMemorySessionLifecycleStore();
    await store.open("contract-sid", "contract-subject", liveSession().expiresAt);
    return store;
};
const claim = () => cookieClaim({
    session: { isAuthenticated: true, sid: "contract-sid", user: { id: "contract-subject" } },
});
/** A requirement whose `admit` counts its calls, delegating to `requirement`'s. */
const counting = (requirement) => {
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
const VERDICTS = new Set(["met", "reauthenticate", "step_up", "unmet"]);
/** Every grade a requirement is asked about: all but `remediation`, which admission never asks about. */
const ASKED_GRADES = ADMISSION_GRADES.filter((grade) => grade !== "remediation");
/** The action the suite admits with, registered on each resolver it builds. */
const CONTRACT_ACTIONS = { "contract.action": { grade: "use" } };
/** The contract's cases over the requirement `input` describes. */
export function sessionRequirementContract(input) {
    const { key, fixture, issuer, build, withOutage, primary } = input;
    const liveInput = (grade) => {
        const session = liveSession();
        return {
            session: viewOfLive(session),
            authentication: requirementSession(session),
            carrier: "cookie",
            subject: session.sub,
            action: { name: "contract.action", grade },
            asks: undefined,
            now: NOW(),
        };
    };
    const cases = [
        {
            name: "name equals its key, and a fixture never declares the second-factor authority",
            run: async () => {
                const requirement = build();
                assert.equal(requirement.name, key, "a requirement's name is the key it is contributed under");
                if (fixture) {
                    // As registration reads it: anything but a boolean does not register.
                    assert.notEqual(registered(requirement, issuer).secondFactorAuthority, true, "a fixture never declares the second-factor authority: boot binds the authority to core's MFA ports");
                }
            },
        },
        {
            name: "reach holds non-empty strings, no primary's marker, no second-factor value unless the requirement declares the second-factor authority, and — in this release — nothing at all unless it does; stepUpPage is set when reach is not empty, and is valid when set",
            // Registration validates the page; the seal boot runs, which the
            // resolver runs too, holds the reach to its rules. The resolver's
            // refusal names its allowAnyReach option, which is for core's own
            // tests: a requirement that keeps this case passes without it.
            run: async () => {
                resolverForTests([build()], issuer === undefined ? {} : { issuer });
            },
        },
        {
            name: "remediations are the requirement's own routes — <name>.<route> — each once",
            run: async () => {
                // Registration holds the rule; a fixture that breaks it does not register.
                const { name, remediations } = registered(build(), issuer);
                for (const remediation of remediations) {
                    assert.ok(remediation.startsWith(`${name}.`), `"${remediation}" is not a route of "${name}"`);
                }
                assert.equal(new Set(remediations).size, remediations.length, "a remediation is declared once");
            },
        },
        {
            name: "hintKeys are hint names",
            // Registration refuses a list with a key that is not a hint name, so
            // a requirement registered is one whose keys all are.
            run: async () => {
                registered(build(), issuer);
            },
        },
        {
            name: "admit is never called with a dead session",
            run: async () => {
                const requirement = counting(build());
                const admission = await admitSession({
                    userSessionStore: storeAnswering(null),
                    sessionLifecycleStore: await openedLifecycle(),
                    subjectRevocation: undefined,
                    requirements: resolverForTests([requirement], {
                        ...(issuer === undefined ? {} : { issuer }),
                        actions: CONTRACT_ACTIONS,
                    }),
                    acrTable: readAcrTable({}),
                    logger: undefined,
                    auditSink: undefined,
                }, { claim: claim(), action: "contract.action" });
                assert.equal(admission.outcome, "not_live");
                assert.equal(requirement.calls(), 0, "admit was called about a session that is not live");
                // Not vacuous: the same requirement is asked about a live one.
                await admitSession({
                    userSessionStore: storeAnswering(liveSession()),
                    sessionLifecycleStore: await openedLifecycle(),
                    subjectRevocation: undefined,
                    requirements: resolverForTests([requirement], {
                        ...(issuer === undefined ? {} : { issuer }),
                        actions: CONTRACT_ACTIONS,
                    }),
                    acrTable: readAcrTable({}),
                    logger: undefined,
                    auditSink: undefined,
                }, { claim: claim(), action: "contract.action" });
                assert.equal(requirement.calls(), 1, "admit was not asked about a live session");
            },
        },
        {
            name: "admit is never called for a remediation action",
            run: async () => {
                const requirement = counting(build());
                const [remediation] = requirement.remediations;
                if (remediation === undefined)
                    return;
                const requirements = resolverForTests([requirement], issuer === undefined ? {} : { issuer });
                // The action core issued for the route, to the object that
                // registered, not through the resolver.
                const issued = issuedRemediationActions(requirement)?.[remediation.slice(requirement.name.length + 1)];
                assert.ok(issued !== undefined, `core issued no action for "${remediation}"`);
                const admission = await admitSession({
                    userSessionStore: storeAnswering(liveSession()),
                    sessionLifecycleStore: await openedLifecycle(),
                    subjectRevocation: undefined,
                    requirements,
                    acrTable: readAcrTable({}),
                    logger: undefined,
                    auditSink: undefined,
                }, { claim: claim(), action: issued });
                assert.equal(admission.outcome, "admitted");
                assert.equal(requirement.calls(), 0, "admit was called for the requirement's own remediation");
            },
        },
        {
            name: "admit answers a verdict, and a step_up only when stepUpPage is set",
            run: async () => {
                for (const grade of ASKED_GRADES) {
                    const requirement = build();
                    const verdict = await requirement.admit(liveInput(grade));
                    assert.ok(typeof verdict === "object" &&
                        verdict !== null &&
                        VERDICTS.has(String(verdict.outcome)), `admit answered something that is not a verdict for the ${grade} grade`);
                    const { outcome, whenStillUnmet } = verdict;
                    if (outcome === "step_up") {
                        assert.ok(whenStillUnmet === "reauthenticate" || whenStillUnmet === "unmet", "a step_up says what a session that comes back still unmet is refused for");
                        assert.notEqual(requirement.stepUpPage, undefined, "a step_up is answered only by a requirement that registered where the step-up starts");
                    }
                }
            },
        },
    ];
    if (withOutage !== undefined) {
        cases.push({
            name: "an outage is thrown, never answered met",
            run: async () => {
                await assert.rejects(withOutage().admit(liveInput("use")), "a requirement over a dependency that is down must throw, never answer");
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
                assert.ok(requirement.admitPrimary !== undefined, "a primary was handed in, but the fixture has no admitPrimary: leave `primary` out for a requirement that never interrupts a login");
                const admission = await admitPrimary({
                    userSessionStore: undefined,
                    sessionLifecycleStore: undefined,
                    subjectRevocation: undefined,
                    requirements: resolverForTests([requirement], issuer === undefined ? {} : { issuer }),
                    acrTable: readAcrTable({}),
                    logger: undefined,
                    auditSink: undefined,
                }, primary);
                // A primary the fixture establishes for makes this case vacuous:
                // said so, rather than passed.
                assert.ok(admission.outcome === "interrupt", `the fixture's admitPrimary answered ${admission.outcome} for the primary given, so its interruption cannot be checked: hand in a primary it interrupts, or leave \`primary\` out`);
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
