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
 * The exchange's one reading of core's session lifecycle: whose live session a
 * `sid` names, so the grant's session rule reads no lifecycle answer itself.
 */

import type { SessionLifecycle } from "@o3co/auth-provider-core";

/**
 * The live session `sid` names, as its subject; `not_live` when it is not
 * live (a session closing or closed, or gone); `unavailable` when the
 * lifecycle could not answer. A `liveness` that throws is not caught here.
 */
export async function liveSessionSubject(
	lifecycle: Pick<SessionLifecycle, "liveness">,
	sid: string,
): Promise<{ readonly subject: string } | "not_live" | "unavailable"> {
	const answer = await lifecycle.liveness(sid);
	switch (answer.outcome) {
		case "live":
			return { subject: answer.session.sub };
		case "not_live":
			return "not_live";
		default:
			return "unavailable";
	}
}
