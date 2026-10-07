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
 * What a login is answered: every requirement's `admitPrimary` asked in
 * registration order, the first interruption winning, else an
 * `Establishment`. Both answers are branded here through module-private
 * `WeakSet`s, so a copy or a look-alike is neither.
 */
import { loggableError } from "../logging/loggableError.mjs";
import { isObject, nonEmptyString } from "./input-values.mjs";
import { checkInterruptionAnswer } from "./interruption-answer.mjs";
import { continuationOf } from "./primary.mjs";
/** The establishments `admitPrimary`, `resumePrimary` and `establishWithoutAsking` built. */
const knownEstablishments = new WeakSet();
/** The interruptions `admitPrimary` and `resumePrimary` answered. */
const knownInterruptions = new WeakSet();
/** Whether `value` is an `Establishment` one of the three built: a copy, or an object shaped like one, is not. */
export function isEstablishment(value) {
    return typeof value === "object" && value !== null && knownEstablishments.has(value);
}
/** Whether `value` is an interruption `admitPrimary` or `resumePrimary` answered: a copy, or an object shaped like one, is not. */
export function isInterruptAdmission(value) {
    return typeof value === "object" && value !== null && knownInterruptions.has(value);
}
/**
 * Builds and brands the `Establishment` of `primary`: the one `isEstablishment`
 * accepts. Called only by `admit.mts` (`establishWithoutAsking`) and by
 * `askEvery`, once every requirement answered `establish`.
 */
export const establish = (primary) => {
    const built = Object.freeze({ primary });
    knownEstablishments.add(built);
    return built;
};
/** An outage at establishment: logged once, at error, object-first, with the requirement's name and the projection. */
const unavailableAtEstablishment = (deps, store, err) => {
    deps.logger?.error({ store, phase: "establishment", err: loggableError(err) }, "session_admission_unavailable");
    return { outcome: "unavailable", store };
};
/**
 * Asks every requirement with `admitPrimary` not in `done`, in registration
 * order, about `composed`; one that completed is not asked again in this
 * login, whatever it added. The first interruption wins, carrying the
 * continuation and an `open` that validates the answer. A throw, or an
 * answer that is neither `establish` nor an interruption, is `unavailable`.
 * Called only by `admit.mts` (`admitPrimary`, `resumePrimary`), after its
 * checks of the primary.
 */
export async function askEvery(deps, requirements, composed, primary, done) {
    const completed = new Set(done.map((entry) => entry.requirement));
    for (const [name, requirement] of requirements.entries()) {
        const ask = requirement.admitPrimary;
        if (ask === undefined || completed.has(name))
            continue;
        let answer;
        try {
            answer = await ask.call(requirement, composed);
        }
        catch (err) {
            return unavailableAtEstablishment(deps, name, err);
        }
        if (answer === "establish")
            continue;
        // The answer's `open` is read once, here.
        const open = isObject(answer) ? answer.open : undefined;
        if (typeof open === "function") {
            // The continuation names who interrupted: `resumePrimary` accepts
            // that requirement's completion alone.
            const continuation = continuationOf(primary, done, name);
            const interruption = Object.freeze({
                outcome: "interrupt",
                requirement: name,
                continuation,
                open: async (sessionId) => {
                    if (nonEmptyString(sessionId) === undefined) {
                        throw new RangeError("open: the session id must be a non-empty string");
                    }
                    // The requirement persists what core built.
                    return checkInterruptionAnswer(await open.call(answer, sessionId, continuation), name, requirement.hintKeys);
                },
            });
            knownInterruptions.add(interruption);
            return interruption;
        }
        return unavailableAtEstablishment(deps, name, new TypeError("a requirement answered something that is neither establish nor an interruption"));
    }
    return { outcome: "establish", establishment: establish(composed) };
}
