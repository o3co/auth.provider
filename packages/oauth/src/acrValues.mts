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
 * advertises as `acr_values_supported` (the MFA ADR's D15): the configured
 * `oauth.authorize.acrValues`, less every entry nothing this composition
 * installs can satisfy — core's `vouchableAcrTable` over what the composition
 * can produce. The router and the discovery contribution compute it from the
 * same inputs, so they cannot disagree; the router alone says at boot what it
 * dropped.
 */

import {
	type AcrTable,
	auditErrorList,
	auditErrorText,
	type Logger,
	producibleAmr,
	readMfaMode,
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
 * - No second factor can: `/authorize` consults no `mfaCoordinator` before
 *   D17's single decision (the MFA ADR's build order, step 13), which adds
 *   the coordinator's `secondFactorMethods` here.
 * - A federation installed makes every entry satisfiable: every federation's
 *   upstream `amr` is recorded beside `fed` and counts, as #481 shipped,
 *   until the build order's step 5 lets a federation be untrusted and
 *   narrows `trustedFederation` to the trusted ones.
 *
 * `federations` is the map a composition installed, read when this runs: at
 * composition, after every federation's contribution has registered.
 */
export const vouchableAcrValues = (
	configured: AcrTable,
	federations: ReadonlyMap<string, unknown> | undefined,
): { readonly table: AcrTable; readonly dropped: readonly UnsatisfiableAcrValue[] } => {
	const federationInstalled = federations !== undefined && federations.size > 0;
	return vouchableAcrTable(
		configured,
		producibleAmr({
			secondFactorMethods: undefined,
			federationInstalled,
			trustedFederation: federationInstalled,
		}),
	);
};

/**
 * One line per dropped entry, once, at composition: `warn` — the operator
 * configured an `acr` this deployment can never meet — except under
 * `mfa.mode = "off"` for an entry only a second factor would meet, which is
 * the operator's choice and is said at `info`, so an MFA-off deployment that
 * keeps the template's MFA entries is not warned at every boot. The entry is
 * the operator's text, bounded as a log line bounds text all the same.
 */
export const logUnsatisfiableAcrValues = (
	dropped: readonly UnsatisfiableAcrValue[],
	config: unknown,
	logger: Logger,
): void => {
	// `undefined` — absent, or a value core's schema refuses at boot — reads as
	// core's default until the flip, `"off"` (D19).
	const mfaOff = (readMfaMode(config) ?? "off") === "off";
	for (const entry of dropped) {
		const unproducible = auditErrorList(entry.unproducible);
		const fields = {
			acr: auditErrorText(entry.acr),
			unproducible,
			...(unproducible.length < entry.unproducible.length
				? { unproducibleCount: entry.unproducible.length }
				: {}),
		};
		if (mfaOff && entry.forWantOfSecondFactor) logger.info(fields, ACR_VALUE_UNSATISFIABLE);
		else logger.warn(fields, ACR_VALUE_UNSATISFIABLE);
	}
};
