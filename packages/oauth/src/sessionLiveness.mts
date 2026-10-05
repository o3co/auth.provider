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

import type { SessionLifecycle, SessionLiveness } from "@o3co/auth-provider-core";

/**
 * Whether the session a token names is live, asked of core's session
 * lifecycle. The lifecycle refuses a sid it cannot hold as a key with a
 * `RangeError` before it reads anything; such a sid names no session it
 * knows, so it is answered `not_live`.
 */
export async function tokenSessionLiveness(
	lifecycle: SessionLifecycle,
	sid: string,
): Promise<SessionLiveness> {
	try {
		return await lifecycle.liveness(sid);
	} catch (error) {
		if (error instanceof RangeError) return { outcome: "not_live" };
		throw error;
	}
}
