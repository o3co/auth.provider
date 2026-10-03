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
 * boot/token-settings-slot.mts: what boot does for the `oauthTokenSettings`
 * slot. Whatever fills it — a host's bootstrap or override value, or a
 * provider's — enters the component map as the snapshot
 * `checkOAuthTokenSettings` answers: held to the contract, and to the
 * lifetimes core resolves from the configuration, read once and frozen. So
 * every reader of the slot reads one value that was checked, and a reader
 * holding the slot alone need not hold it to the configuration again.
 */

import type { ComponentKey } from "../modules/manifest/component-map.mjs";
import {
	checkOAuthTokenSettings,
	lifetimeBeyondConfiguration,
	lifetimeBeyondConfigurationMessage,
} from "../token-settings/check.mjs";
import type { OAuthTokenSettings } from "../token-settings/types.mjs";
import { BootError } from "./types.mjs";

/** Where the slot's value came from: a host map, or a module's `provides`. */
type TokenSettingsSource =
	| { readonly source: "bootstrapComponents" | "overrideComponents" }
	| { readonly source: "provides"; readonly module: string };

/** What stage 3 does to the `oauthTokenSettings` slot. */
export interface TokenSettingsSlot {
	/**
	 * Before any provider runs: replaces a host's value in the slot with its
	 * snapshot. The override's source wins when the override map carries the
	 * key, as its value does.
	 */
	beforeProviders(fromOverride: boolean): void;
	/** The value the working map holds for a provider's `value` under `key`. */
	provided(key: ComponentKey, value: unknown, module: string): unknown;
}

/**
 * `value` as the slot holds it: the snapshot of its contract check, bounded
 * by the lifetimes `config` resolves.
 *
 * @throws RangeError naming the member, for a value that breaks the
 *   contract or whose read throws.
 * @throws BootError `token-settings-lifetime-exceeds-configuration` (stage
 *   `materializeComponents`), naming the source, the member and both
 *   values, for a lifetime longer than the configured one.
 */
function snapshotOf(
	value: unknown,
	config: unknown,
	from: TokenSettingsSource,
): OAuthTokenSettings {
	const snapshot = checkOAuthTokenSettings(value);
	const found = lifetimeBeyondConfiguration(snapshot, config);
	if (found === undefined) return snapshot;
	throw new BootError({
		stage: "materializeComponents",
		reason: "token-settings-lifetime-exceeds-configuration",
		message: lifetimeBeyondConfigurationMessage(
			found,
			from.source === "provides" ? `module "${from.module}"` : from.source,
		),
		details: {
			reason: "token-settings-lifetime-exceeds-configuration",
			componentKey: "oauthTokenSettings",
			...from,
			member: found.member,
			slotSeconds: found.slotSeconds,
			configurationSeconds: found.configurationSeconds,
		},
	});
}

/**
 * Stage 3's handling of the `oauthTokenSettings` slot in `components`, the
 * working map, against `config`, the configuration stage 1 parsed.
 *
 * - A host's value is replaced before any provider runs. A lifetime beyond
 *   the configuration's is refused as a BootError; one stage 1 saw is
 *   already refused there, so this one is a value that answered stage 1
 *   differently. A value that breaks the contract is refused with the
 *   check's RangeError, naming the member.
 * - A provider's value is replaced as it is materialised; its refusal is
 *   the caller's to report, after its rollback (the RangeError as a failed
 *   provider, the BootError as it is). A cleanup is still handed the
 *   provider's own value.
 * - An empty key stays empty: a composition without the slot reads the
 *   configuration.
 */
export function tokenSettingsSlotFor(
	components: Record<string, unknown>,
	config: unknown,
): TokenSettingsSlot {
	return {
		beforeProviders(fromOverride) {
			if (!Object.hasOwn(components, "oauthTokenSettings")) return;
			components.oauthTokenSettings = snapshotOf(components.oauthTokenSettings, config, {
				source: fromOverride ? "overrideComponents" : "bootstrapComponents",
			});
		},
		provided(key, value, module) {
			return key === "oauthTokenSettings"
				? snapshotOf(value, config, { source: "provides", module })
				: value;
		},
	};
}
