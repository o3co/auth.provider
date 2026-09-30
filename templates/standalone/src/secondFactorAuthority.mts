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
 * The template's guard that a second factor it asks for has an authority.
 * When the parsed `mfa.mode` is not `off`, `expectedSessionRequirements`
 * declares `mfa`, and boot refuses the composition unless a module registers
 * it; boot weighs no name, though, so any requirement registered as `mfa`
 * would meet that declaration. This refuses the boot unless the requirement
 * registered as `mfa` declares the second-factor authority — the one
 * requirement core lets reach and add a second factor, bound to its MFA
 * ports — so a requirement merely named `mfa` cannot stand in for MFA. See
 * ADR 2026-09-28-session-admission, D7.
 */

import { type AppConfig, type AppHandle, readMfaMode } from "@o3co/auth-provider-core";

/** The requirement the template declares for MFA: the MFA package's. */
const MFA_REQUIREMENT = "mfa";

/**
 * The parsed `mfa.mode` asks for a second factor, and the requirement
 * registered as `mfa` does not declare the second-factor authority (or none
 * is registered): logins would get no second factor. Thrown after the handle
 * is disposed.
 */
export class MfaRequirementNotAuthorityError extends Error {
	readonly reason = "mfa-requirement-not-second-factor-authority";

	constructor(mode: string, registered: boolean) {
		super(
			`mfa.mode is "${mode}", and ${registered ? `the session requirement registered as "${MFA_REQUIREMENT}" does not declare the second-factor authority` : `no session requirement is registered as "${MFA_REQUIREMENT}"`}: no login would be asked for a second factor. Install the MFA package's modules (mfaModules), whose requirement declares it, or set mfa.mode = "off" (MFA_MODE)`,
		);
		this.name = "MfaRequirementNotAuthorityError";
	}
}

/**
 * Once boot has registered the session requirements, and before the server
 * listens: under a parsed `mfa.mode` other than `off`, disposes `handle` and
 * refuses the boot (`MfaRequirementNotAuthorityError`) unless the requirement
 * registered as `mfa` declares the second-factor authority. Under `off` it
 * asks nothing. The mode is read as `expectedSessionRequirements` reads it.
 */
export async function requireMfaSecondFactorAuthority(
	switches: AppConfig,
	handle: Pick<AppHandle, "components" | "dispose">,
): Promise<void> {
	const mode = readMfaMode(switches) ?? "off";
	if (mode === "off") return;
	const registered = handle.components.sessionRequirementResolver?.get(MFA_REQUIREMENT);
	if (registered?.secondFactorAuthority === true) return;
	await handle.dispose();
	throw new MfaRequirementNotAuthorityError(mode, registered !== undefined);
}
