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
 * The prefixes whose limit a verifier sets itself: the attempts a credential
 * check allows, counted on the attempt counter at the owner's setting and
 * never by a rate limiter. The bundled limiter modules' sections may not name
 * one in their `limits`; the builders and constructors take `limits` as given.
 * The setting each is made at is what a refusal points to. The one place core
 * names another package's prefix and setting.
 */

import type { z } from "zod";

const VERIFIER_LIMIT_SETTINGS: ReadonlyMap<string, string> = new Map([
	["login", "session.rateLimit.login"],
	["device_verification", "device-grant.rateLimit"],
]);

/**
 * Where the limit under `prefix` is set when a verifier owns it — the
 * setting a refusal names — or `undefined` for any other prefix.
 */
export const verifierLimitSetting = (prefix: string): string | undefined =>
	VERIFIER_LIMIT_SETTINGS.get(prefix);

/** Why a limiter's `limits` may not name `prefix`, or `undefined` when it may. */
const verifierLimitProblem = (prefix: string): string | undefined => {
	const setting = verifierLimitSetting(prefix);
	return setting === undefined
		? undefined
		: `"${prefix}" is a verifier's own attempt limit, which no limiter's limits may set: set ${setting} instead`;
};

/**
 * A limiter section's `limits` check (`superRefine`): an issue at each entry
 * naming a verifier's prefix.
 */
export function refuseVerifierLimitEntries(
	limits: Readonly<Record<string, unknown>>,
	ctx: z.RefinementCtx,
): void {
	for (const prefix of Object.keys(limits)) {
		const problem = verifierLimitProblem(prefix);
		if (problem !== undefined) ctx.addIssue({ code: "custom", path: [prefix], message: problem });
	}
}
