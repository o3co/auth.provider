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
 * What modules outside the federation-grants module read of its section, the
 * `federationGrantPolicy` slot they read it through, and the check a reader
 * holds the slot's value to.
 *
 * `federation-grants {}` is that module's section: it parses it and provides
 * this, and a reader requires nothing of the section. A composition that
 * holds no slot has grants off: a composition without the federation-grants
 * module, or one where the module is switched off and so provides nothing. The value a switched-on
 * module provides therefore always says `enabled: true`; `enabled: false`
 * comes only from a value a host fills itself.
 *
 * Not core's `grantPolicy`, the gate token-minting paths consult (allow or
 * deny, optionally narrowing the scope and audience): this is the federation
 * grants' switch and keep policy, and "grant" here is a federation grant,
 * never an OAuth grant type.
 *
 * Contract suite and test double: `federationGrantPolicyContract`,
 * `createTestFederationGrantPolicy` on `@o3co/auth-provider-core/testing`.
 */

import { describeValue } from "../errors/describe-value.mjs";

export interface FederationGrantPolicy {
	/**
	 * `federation-grants.enabled`: whether federation grants exist in this
	 * deployment, so that what ends a subject's access must end its grants too.
	 */
	readonly enabled: boolean;
	/**
	 * The keep policy in force: whether a subject-wide revocation may be asked
	 * to leave the subject's established grants standing
	 * (`federation-grants.allowKeepOnSubjectRevocation`, read with
	 * `resolveFederationGrantKeepPolicy`). Always `false` while `enabled` is
	 * `false`: an allowance to keep grants a deployment does not have is an
	 * allowance over nothing, so a reader reads this member alone.
	 */
	readonly allowKeepOnSubjectRevocation: boolean;
}

const WHY =
	"A reader reads the federation grants' switch and keep policy from the federationGrantPolicy " +
	"a composition holds and from nothing else, so a member the slot lacks or gets wrong is refused " +
	"rather than read as grants off.";

/** The value a refusal names: `none` for a member the slot lacks, otherwise its kind. */
const shown = (value: unknown): string => (value === undefined ? "none" : describeValue(value));

/**
 * A member of a host's value, read once. A read that throws — a getter, a
 * proxy trap — is refused, naming the member, rather than answered.
 */
const readOnce = (member: string, read: () => unknown): unknown => {
	try {
		return read();
	} catch (err) {
		throw new RangeError(
			`federationGrantPolicy.${member} could not be read: reading it threw. ${WHY}`,
			{ cause: err },
		);
	}
};

const SWITCHES = ["enabled", "allowKeepOnSubjectRevocation"] as const;

/**
 * The `federationGrantPolicy` a composition holds, as a frozen copy: each
 * member read from `value` exactly once and held to its contract rule, so
 * what was checked is what is answered and a later change to `value` changes
 * nothing a reader holds. Members no reader reads are not carried.
 *
 * A reader calls it on the slot it is handed before reading a member; a
 * reader handed no slot has grants off and calls nothing.
 *
 * @throws RangeError naming the first member that is missing, not a boolean
 *   or whose read throws; an `allowKeepOnSubjectRevocation` of `true` beside
 *   an `enabled` of `false`; or the slot when it holds no policy object.
 */
export function checkFederationGrantPolicy(value: unknown): FederationGrantPolicy {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new RangeError(
			`federationGrantPolicy must be the policy object its contract describes, and the composition's slot holds ${shown(value)}. ${WHY}`,
		);
	}
	const slot = value as Record<string, unknown>;
	const read = new Map<(typeof SWITCHES)[number], unknown>(
		SWITCHES.map((name) => [name, readOnce(name, () => slot[name])]),
	);
	for (const [name, member] of read) {
		if (typeof member !== "boolean") {
			throw new RangeError(
				`federationGrantPolicy.${name} must be true or false, and the composition's slot carries ${shown(member)}. ${WHY}`,
			);
		}
	}
	const enabled = read.get("enabled") as boolean;
	const allowKeepOnSubjectRevocation = read.get("allowKeepOnSubjectRevocation") as boolean;
	if (!enabled && allowKeepOnSubjectRevocation) {
		throw new RangeError(
			"federationGrantPolicy.allowKeepOnSubjectRevocation must be false while " +
				"federationGrantPolicy.enabled is false, and the composition's slot carries true: an " +
				`allowance to keep grants a deployment does not have is an allowance over nothing. ${WHY}`,
		);
	}
	return Object.freeze({ enabled, allowKeepOnSubjectRevocation });
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/**
		 * The federation grants' switch and keep policy, provided by the module
		 * that owns `federation-grants {}`; absent, grants are off. Not core's
		 * `grantPolicy`, the gate token-minting paths consult (allow or deny,
		 * optionally narrowing the scope and audience).
		 */
		readonly federationGrantPolicy?: FederationGrantPolicy;
	}
}
