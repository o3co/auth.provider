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
import { isObject } from "./input-values.mjs";
/** The requirements already said to have stepped up without a page, once per process each. */
const pagelessStepUps = new Set();
/** The requirements already said to have stepped up over no session, once per process each. */
const sessionlessStepUps = new Set();
const VERDICTS = new Set(["met", "reauthenticate", "step_up", "unmet"]);
/** A requirement's answer read once — `outcome` and `whenStillUnmet` — into a plain object; anything that is not an object as it is. */
export const copyVerdict = (answer) => isObject(answer) ? { outcome: answer.outcome, whenStillUnmet: answer.whenStillUnmet } : answer;
/** Whether `value` is one of the four verdicts, its `step_up` with a `whenStillUnmet` (and no page: the registered one answers). */
export const isVerdict = (value) => isObject(value) &&
    typeof value.outcome === "string" &&
    VERDICTS.has(value.outcome) &&
    (value.outcome !== "step_up" ||
        value.whenStillUnmet === "reauthenticate" ||
        value.whenStillUnmet === "unmet");
/**
 * A requirement's `step_up` as admission takes it: over no session (no
 * store, or a token carrier without a record) it is `reauthenticate`, since
 * nothing can be stepped up onto no session and a login can; from a
 * requirement that registered no page it is `unmet`, since nothing could
 * finish the trip. Each is logged once per process per name. So a `step_up`
 * always carries a live session and a page.
 */
export function stepUpVerdict(name, requirement, whenStillUnmet, live, deps) {
    if (live === null) {
        if (!sessionlessStepUps.has(name)) {
            sessionlessStepUps.add(name);
            deps.logger?.warn({ requirement: name }, "session_admission_step_up_without_session");
        }
        return { outcome: "reauthenticate", requirement: name };
    }
    const page = requirement.stepUpPage;
    if (page === undefined) {
        if (!pagelessStepUps.has(name)) {
            pagelessStepUps.add(name);
            deps.logger?.warn({ requirement: name }, "session_admission_step_up_without_page");
        }
        return { outcome: "unmet", requirement: name };
    }
    return {
        outcome: "step_up",
        requirement: name,
        stepping: requirement,
        session: live.session,
        view: live.view,
        page,
        whenStillUnmet,
    };
}
/**
 * The action as the requirements see it, one frozen object every requirement
 * is handed: a registered action as registered, or the `remediation` core
 * issued to one of these requirements (the request check refuses any other),
 * which skips them.
 */
export function effectiveAction(asked) {
    return asked.grade === "remediation"
        ? asked
        : Object.freeze({ name: asked.name, grade: asked.grade });
}
