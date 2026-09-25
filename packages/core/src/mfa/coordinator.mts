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
 * The `mfaCoordinator` slot: what `session` and `oauth` consult about MFA
 * (the MFA ADR's D8), and `MFA_ABSENCE_POLICY`, which makes leaving it
 * unfilled a statement (D20).
 *
 * Declared in core and filled by the MFA package, so that neither the login
 * route nor `/authorize` imports an optional feature — `session` and `oauth`
 * do not depend on each other, and neither should depend on MFA.
 */

import type { AbsencePolicy } from "../modules/manifest/absence-policy.mjs";

/** A primary authentication that has just succeeded, as the login route hands it over. */
export interface PrimaryAuthentication {
	/** `User.id`. */
	readonly subject: string;
	/** `"pwd"` from `POST /session/login`; a federation's `"fed"`, later. */
	readonly method: string;
	readonly amr: readonly string[];
	readonly authTime: Date;
	/** What `req.session.user` will hold. */
	readonly user: Readonly<Record<string, unknown>>;
	/** Already held to `session.redirectAllowlist`. */
	readonly redirectTo: string | undefined;
	readonly request: { readonly ip?: string; readonly userAgent?: string };
}

/**
 * What a login asks after its primary authentication, and what `/authorize`
 * asks about a step-up.
 *
 * Two calls, because the express session is regenerated between them: the
 * subject's factors are read before anything is written, and the
 * transaction is bound to the session id the browser will hold.
 */
export interface MfaCoordinator {
	/** The `amr` values the installed factors can add: what a step-up can reach. */
	readonly secondFactorMethods: ReadonlySet<string>;
	/**
	 * Reads the subject's factors and the enrollment witness, and decides:
	 * log in as before, challenge a factor, or enroll one. Throws on an
	 * outage; the caller answers `503` and writes nothing.
	 */
	decideAfterPrimary(p: PrimaryAuthentication): Promise<"none" | "challenge" | "enroll">;
	/** After the caller regenerated the express session: opens the login transaction, bound to the new id. */
	openLoginTransaction(
		p: PrimaryAuthentication,
		decision: "challenge" | "enroll",
		sessionId: string,
	): Promise<{ readonly id: string; readonly expiresInSeconds: number }>;
}

/**
 * The declared absence of a coordinator (D20): `mfa.mode = "off"`. A module
 * that reads `mfaCoordinator` attaches this policy, so a composition that
 * leaves the slot unfilled refuses to boot unless it writes that line.
 *
 * One shared constant, like the other absence policies, so the boot error's
 * advice cannot depend on which module tripped it.
 */
export const MFA_ABSENCE_POLICY = {
	configKey: ["mfa", "mode"],
	absentValue: "off",
	hint:
		"Without a coordinator no login and no authorization request can ask for a second factor, " +
		"and none is ever verified: every password login signs the user in with the password alone.",
} as const satisfies AbsencePolicy;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** What the login route and `/authorize` consult about MFA (the MFA ADR's D8). */
		readonly mfaCoordinator?: MfaCoordinator;
	}
}
