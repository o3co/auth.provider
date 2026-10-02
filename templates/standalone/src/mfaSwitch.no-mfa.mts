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
 * The template's MFA switch in a project scaffolded without MFA
 * (`create-auth-provider --no-mfa`), which does not install the MFA package:
 * the switch is off and nothing turns it on. It installs nothing of MFA,
 * hands boot nothing of the `mfa` section, and leaves the `acr` table as
 * written.
 *
 * Asking for MFA is refused before boot with a `RangeError` that names the
 * keys and variables and quotes no value: `MFA_MODE` or a file's `mfaMode`
 * other than `off`, and an `mfa.mode` the configuration writes other than
 * `off`. A project without MFA never runs while its configuration says
 * logins ask for a second factor.
 *
 * Exports the names and signatures the template's other modules call.
 */

import type { Module } from "@o3co/auth-provider-core";
import { type Adapters, isPlainSection } from "./sections.mjs";

/** The composition root's MFA switch, a key of its own. No module may be named after it. */
export const MFA_SWITCH = "mfaMode";

/** The composition root's MFA switch: off, the one value a project without MFA has. */
export type MfaSwitch = "off";

const NOT_INSTALLED =
	"this project was scaffolded without MFA (create-auth-provider --no-mfa) and does not install the MFA package";

/**
 * `off`, when neither `MFA_MODE` in `env` nor `mfaMode` in `resolved` (the
 * template's own layers) says otherwise; a `RangeError` naming both when one
 * does.
 */
export function readMfaSwitch(
	resolved: Readonly<Record<string, unknown>>,
	env: Readonly<Record<string, string>>,
): MfaSwitch {
	const written = resolved[MFA_SWITCH];
	const variable = env.MFA_MODE;
	if (
		(written !== undefined && written !== "off") ||
		(variable !== undefined && variable !== "off")
	) {
		throw new RangeError(
			`${MFA_SWITCH} (MFA_MODE) is set to other than off, and ${NOT_INSTALLED}. Unset MFA_MODE and ${MFA_SWITCH}, or set them to off`,
		);
	}
	return "off";
}

/** No module: the switch is off. */
export function mfaModulesFor(_options: {
	readonly mode: MfaSwitch;
	readonly adapters: Pick<Adapters, "mfaFactorStore" | "mfaTransactionStore">;
	readonly storeTransport: unknown;
	readonly environment: string | undefined;
}): Module[] {
	return [];
}

/**
 * What boot is handed of the `mfa` section: none unless a loaded module owns
 * it (`owned`), and then `resolved`'s section as it is. Refuses an
 * `mfa.mode` the composition's own layers (`written`, their `mfa`) write
 * other than `off`, or an `mfa` written as a value.
 */
export function mfaSectionForBoot(options: {
	readonly mode: MfaSwitch;
	readonly written: unknown;
	readonly resolved: Readonly<Record<string, unknown>>;
	readonly owned: boolean;
	readonly storeCalled: boolean;
	readonly env: Readonly<Record<string, string>>;
}): unknown {
	const { written } = options;
	const writtenMode =
		written === undefined ? undefined : isPlainSection(written) ? written.mode : null;
	if (writtenMode !== undefined && writtenMode !== "off") {
		throw new RangeError(
			`mfa.mode is written in the configuration and is not off, while ${MFA_SWITCH} (MFA_MODE) is off: ${NOT_INSTALLED}. Remove mfa.mode`,
		);
	}
	return options.owned ? options.resolved.mfa : undefined;
}

/** `oauth` as it is: without MFA the template adds nothing to the `acr` table. */
export function oauthForBoot(_mode: MfaSwitch, oauth: unknown): unknown {
	return oauth;
}
