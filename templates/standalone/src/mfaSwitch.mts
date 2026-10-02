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
 * The composition root's own key `mfaMode` (`MFA_MODE`): whether the template
 * installs MFA. Phase one reads it alone, before the modules are chosen, with
 * the template's own schema; boot is never handed it. A value the schema
 * refuses is refused here, naming the key and its variable and never the
 * value.
 */

import { type MfaSwitch, mfaSwitchSchema } from "./sections.mjs";

/** The composition root's MFA switch, a key of its own. No module may be named after it. */
export const MFA_SWITCH = "mfaMode";

/**
 * `mfaMode` from `resolved` — the template's own layers over its
 * `config/reference.conf` — parsed with the template's schema. A value the
 * schema refuses is a `RangeError` naming `mfaMode` and `MFA_MODE`.
 */
export function readMfaSwitch(resolved: Readonly<Record<string, unknown>>): MfaSwitch {
	const result = mfaSwitchSchema.safeParse(resolved[MFA_SWITCH]);
	if (!result.success) {
		throw new RangeError(
			`Config validation failed — ${MFA_SWITCH} (MFA_MODE): ${result.error.issues
				.map((issue) => issue.message)
				.join("; ")}`,
			{ cause: result.error },
		);
	}
	return result.data;
}
