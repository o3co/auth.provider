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
 * The acr table `/authorize` answers `acr_values` from and discovery
 * advertises as `acr_values_supported`: the configured
 * `oauth.authorize.acrValues` less every entry nothing this composition
 * installs can satisfy (see ADRs 2026-09-25-multi-factor-authentication and
 * 2026-09-28-session-admission). The router and the discovery contribution
 * compute it from the same inputs, so they cannot disagree; the router alone
 * logs at boot what it dropped.
 */

import {
	type AcrTable,
	auditErrorList,
	auditErrorText,
	type FederationSettings,
	type Logger,
	producibleAmr,
	SECOND_FACTOR_AMR,
	type UnsatisfiableAcrValue,
	vouchableAcrTable,
} from "@o3co/auth-provider-core";

/** The event name of the boot line for each dropped entry. */
export const ACR_VALUE_UNSATISFIABLE = "acr_value_unsatisfiable";

/**
 * The table this composition vouches for.
 *
 * - `pwd` can always be produced; `fed` once a federation is installed, since
 *   only a federation callback records it.
 * - `reach`, the union of every registered session requirement's reach
 *   (core's `stepUpReach`), is what a step-up can add: the second-factor
 *   values once the MFA requirement is registered, `mfa` among them when an
 *   enabled factor adds it.
 * - An installed federation whose entry in core's `federationSettings` trusts
 *   its upstream IdP's `amr` (`trustsUpstreamAmr`, true only beside `enabled`)
 *   makes every entry satisfiable: the callback records what that IdP asserts
 *   beside `fed`. One that does not, or that the settings hold no entry for,
 *   adds `fed` alone; its IdP's values meet no `acr`.
 *
 * Runs at composition, after every name-keyed contribution has registered.
 * The federation callback reads the same settings, so the two cannot
 * disagree; boot refuses a switch that is given but unusable when it fills
 * them.
 */
export const vouchableAcrValues = (
	configured: AcrTable,
	federations: ReadonlyMap<string, unknown> | undefined,
	federationSettings: FederationSettings,
	reach: ReadonlySet<string>,
): { readonly table: AcrTable; readonly dropped: readonly UnsatisfiableAcrValue[] } => {
	const installed = [...(federations?.keys() ?? [])];
	const trustedFederation = installed.some(
		(name) =>
			Object.hasOwn(federationSettings, name) &&
			federationSettings[name]?.trustsUpstreamAmr === true,
	);
	return vouchableAcrTable(
		configured,
		producibleAmr({
			reach,
			federationInstalled: installed.length > 0,
			trustedFederation,
		}),
	);
};

/**
 * One line per dropped entry, once, at composition: `warn` (an `acr` this
 * deployment can never meet), except `info` for an entry that lacks only a
 * second factor while no registered requirement reaches one, so an MFA-off
 * deployment keeping the template's MFA entries is not warned at every boot.
 * `mfa.mode` is read nowhere here. The entry is operator text, bounded like
 * any logged text.
 */
export const logUnsatisfiableAcrValues = (
	dropped: readonly UnsatisfiableAcrValue[],
	reach: ReadonlySet<string>,
	logger: Logger,
): void => {
	const secondFactorReachable = [...reach].some((value) => SECOND_FACTOR_AMR.has(value));
	for (const entry of dropped) {
		const unproducible = auditErrorList(entry.unproducible);
		const fields = {
			acr: auditErrorText(entry.acr),
			unproducible,
			...(unproducible.length < entry.unproducible.length
				? { unproducibleCount: entry.unproducible.length }
				: {}),
			// An alternative that requires nothing is never met: said, so an entry
			// with nothing else to name is not logged with an empty list alone.
			...(entry.emptyAlternative ? { emptyAlternative: true } : {}),
		};
		if (entry.forWantOfSecondFactor && !secondFactorReachable) {
			logger.info(fields, ACR_VALUE_UNSATISFIABLE);
		} else {
			logger.warn(fields, ACR_VALUE_UNSATISFIABLE);
		}
	}
};
