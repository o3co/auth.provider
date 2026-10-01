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
 * Step 7 of `admitSession`: the requirements' verdict and the `acr`
 * selection merged by the session-admission ADR's table. The hint of a
 * `step_up` it answers lists only the entries the stepping requirement's own
 * trip can finish. In the met + step_up row, a step-up through the
 * second-factor authority is never offered for `acr_values` onto a session
 * whose store has no `recordSecondFactor` or on which
 * `canRecordSecondFactor` is false: the answer is a new login
 * (`reauthenticate`, `acr`) instead.
 */

import type { AcrSelection } from "./acr.mjs";
import type { Admission, AdmissionDeps, RegisteredRequirement } from "./requirement.mjs";
import type { LiveRecord, RequirementOutcome } from "./requirement-verdict.mjs";

export interface MergeContext {
	/** The live record and admission's view of it; `null` without one. */
	readonly live: LiveRecord | null;
	/** No requested value is in the table: no login can meet the request. */
	readonly noneConfigured: boolean;
	readonly requirements: readonly (readonly [string, RegisteredRequirement])[];
	/** The vouched `amr`. */
	readonly held: readonly string[];
	readonly table: AdmissionDeps["acrTable"];
	/**
	 * Whether a second factor can be recorded on the live session: the store
	 * has the step-up capability and `canRecordSecondFactor` is true. Called
	 * only where the met + step_up row would choose the authority.
	 */
	readonly recordable: () => boolean;
}

/** The merge table of ADR 2026-09-28-session-admission: `R` the requirements' verdict, `A` the acr selection (`undefined` when nothing was asked). */
export function merge(
	R: RequirementOutcome,
	A: AcrSelection | undefined,
	context: MergeContext,
): Admission {
	const { live } = context;
	const session = live?.session ?? null;
	const unmetAcr = (): Admission => ({ outcome: "unmet", requirement: "acr", session });
	switch (R.outcome) {
		case "met":
			if (A === undefined || A.outcome === "met") {
				return { outcome: "admitted", session, view: live?.view ?? null, acr: A?.acr };
			}
			// A selection steps up only over a live session: step 6 hands it an
			// empty reach otherwise.
			if (A.outcome === "unmet" || live === null) return unmetAcr();
			return stepUpThroughOne(A.acrValues, context, live) ?? unmetAcr();
		case "reauthenticate":
			return context.noneConfigured
				? unmetAcr()
				: { outcome: "reauthenticate", requirement: R.requirement, session };
		case "step_up": {
			if (A?.outcome === "unmet") return unmetAcr();
			// The hint: what the stepping requirement's own trip can finish, as
			// in the met + step_up row — never an entry only another reaches.
			return {
				outcome: "step_up",
				requirement: R.requirement,
				session: R.session,
				view: R.view,
				page: R.page,
				acrValues:
					A?.outcome === "step_up"
						? A.acrValues.filter((acr: string) => finishes(context, R.stepping, acr))
						: [],
				whenStillUnmet: A?.outcome === "step_up" ? "unmet" : R.whenStillUnmet,
			};
		}
		case "unmet":
			return A?.outcome === "unmet"
				? unmetAcr()
				: { outcome: "unmet", requirement: R.requirement, session };
	}
}

/** Whether `requirement`'s reach, beside what is held, covers one alternative of the entry `acr`. */
const finishes = (
	context: MergeContext,
	requirement: RegisteredRequirement,
	acr: string,
): boolean =>
	// `acr` is one the selection answered reachable: a key of the table.
	(context.table[acr] as readonly (readonly string[])[]).some(
		(alternative) =>
			alternative.length > 0 &&
			alternative.every((value) => context.held.includes(value) || requirement.reach.has(value)),
	);

/**
 * The `met` + `step_up` row: the page of the first requirement whose own
 * reach covers everything one alternative of a reachable entry lacks, with
 * the entries that requirement alone can finish as the hint — `undefined`
 * when no single requirement covers any, since no one trip can finish it.
 * The second-factor authority is passed over when the session cannot record
 * its trip; when it alone could have finished one, the answer is
 * `reauthenticate` (`acr`).
 */
function stepUpThroughOne(
	reachable: readonly string[],
	context: MergeContext,
	live: LiveRecord,
): Admission | undefined {
	let unrecordable = false;
	for (const [name, requirement] of context.requirements) {
		// What this requirement's reach alone can finish, beside what is held.
		const finishable = reachable.filter((acr: string) => finishes(context, requirement, acr));
		// A requirement whose reach covers an entry registered a page: boot
		// holds a non-empty reach to one. Without one nothing could finish it.
		if (finishable.length > 0 && requirement.stepUpPage !== undefined) {
			if (requirement.secondFactorAuthority && !context.recordable()) {
				unrecordable = true;
				continue;
			}
			return {
				outcome: "step_up",
				requirement: name,
				session: live.session,
				view: live.view,
				page: requirement.stepUpPage,
				// The hint: the entries this one trip can finish, in the request's order.
				acrValues: finishable,
				whenStillUnmet: "unmet",
			};
		}
	}
	return unrecordable
		? { outcome: "reauthenticate", requirement: "acr", session: live.session }
		: undefined;
}
