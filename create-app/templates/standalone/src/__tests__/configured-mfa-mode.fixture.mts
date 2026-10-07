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
 * The MFA switch, `mfaMode`, as this project's own configuration files write
 * it with `MFA_MODE` unset: `{environment}.conf` over `application.conf` over
 * the template's `config/reference.conf`. The template ships it `required`;
 * a project `create-auth-provider --no-mfa` scaffolds writes it `off` at the
 * end of its `application.conf`. A suite whose subject depends on the switch
 * asserts what MFA on (`required`, as the template ships it) or off (as
 * `--no-mfa` writes it) implies, so the suite that ships with a scaffold holds
 * in either project. A project whose files write another mode, such as
 * `optional`, is not what these suites claim to cover.
 *
 * Read with the HOCON parser alone, not through phase one (`readSwitches`),
 * so that a suite about phase one can state what phase one should answer.
 */

import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type Config, empty, parseFile } from "@o3co/ts.hocon";
import { type MfaSwitch, mfaSwitchSchema } from "#/sections.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

/** `mfaMode` as the files selected by `environment` write it, with no variable set. */
export function configuredMfaMode(environment: string): MfaSwitch {
	const resolved = [`${environment}.conf`, "application.conf", "reference.conf"]
		.reduce<Config>(
			(layered, file) => layered.withFallback(parseFile(join(configDir, file), { env: {} })),
			empty(),
		)
		.toObject() as Record<string, unknown>;
	return mfaSwitchSchema.parse(resolved.mfaMode);
}
