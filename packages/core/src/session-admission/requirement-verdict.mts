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
 * What admission's step 5 makes of the requirements: the action's effective
 * grade, each answer read once and held to the four verdicts, and a
 * `step_up` that stands only over a live session from a requirement with a
 * page. Each warning here is said once per process per name.
 */

import type { UserSession } from "../user-sessions/types.mjs";
import type { AdmissionAction } from "./actions.mjs";
import { isObject } from "./input-values.mjs";
import type {
	AdmissionDeps,
	RegisteredRequirement,
	RegisteredStepUpPage,
	RequirementVerdict,
	SessionView,
} from "./requirement.mjs";

/** The requirements already said to have stepped up without a page, once per process each. */
const pagelessStepUps = new Set<string>();

/** The requirements already said to have stepped up over no session, once per process each. */
const sessionlessStepUps = new Set<string>();

const VERDICTS: ReadonlySet<string> = new Set(["met", "reauthenticate", "step_up", "unmet"]);

/** A requirement's answer read once — `outcome` and `whenStillUnmet` — into a plain object; anything that is not an object as it is. */
export const copyVerdict = (answer: unknown): unknown =>
	isObject(answer) ? { outcome: answer.outcome, whenStillUnmet: answer.whenStillUnmet } : answer;

/** Whether `value` is one of the four verdicts, its `step_up` with a `whenStillUnmet` (and no page: the registered one answers). */
export const isVerdict = (value: unknown): value is RequirementVerdict =>
	isObject(value) &&
	typeof value.outcome === "string" &&
	VERDICTS.has(value.outcome) &&
	(value.outcome !== "step_up" ||
		value.whenStillUnmet === "reauthenticate" ||
		value.whenStillUnmet === "unmet");

/** A live record step 2 read, beside admission's view of it. */
export interface LiveRecord {
	readonly session: UserSession;
	readonly view: SessionView;
}

/**
 * Step 5's verdict, with the requirement that gave it. An outage never gets
 * here — step 5 answers `unavailable` itself — and a `step_up` carries the
 * live session it was taken over and the requirement whose reach bounds its
 * hint: `stepUpVerdict` makes one over no session `reauthenticate`.
 */
export type RequirementOutcome =
	| { readonly outcome: "met" }
	| { readonly outcome: "reauthenticate"; readonly requirement: string }
	| {
			readonly outcome: "step_up";
			readonly requirement: string;
			readonly stepping: RegisteredRequirement;
			readonly session: UserSession;
			readonly view: SessionView;
			readonly page: RegisteredStepUpPage;
			readonly whenStillUnmet: "reauthenticate" | "unmet";
	  }
	| { readonly outcome: "unmet"; readonly requirement: string };

/**
 * A requirement's `step_up` as admission takes it: over no session (no
 * store, or a token carrier without a record) it is `reauthenticate`, since
 * nothing can be stepped up onto no session and a login can; from a
 * requirement that registered no page it is `unmet`, since nothing could
 * finish the trip. Each is logged once per process per name. So a `step_up`
 * always carries a live session and a page.
 */
export function stepUpVerdict(
	name: string,
	requirement: RegisteredRequirement,
	whenStillUnmet: "reauthenticate" | "unmet",
	live: LiveRecord | null,
	deps: AdmissionDeps,
): RequirementOutcome {
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
export function effectiveAction(asked: AdmissionAction): AdmissionAction {
	return asked.grade === "remediation"
		? asked
		: Object.freeze({ name: asked.name, grade: asked.grade });
}
