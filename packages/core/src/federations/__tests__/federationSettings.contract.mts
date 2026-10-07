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
 * The contract suite of the `federationSettings` slot, which core alone
 * fills. `federationSettingsContract(input)` holds the settings to what core
 * fills the slot with from `core.federations`: each entry names its type, its
 * two switches are booleans and trust goes only with an enabled entry, its
 * callback URL and upstream identity are non-empty strings where present and
 * an enabled entry has a callback URL, it carries nothing else — no secret —
 * and the map inherits nothing and is frozen with every entry.
 */

import assert from "node:assert/strict";
import type { ConfiguredFederation, FederationSettings } from "#/federations/settings.mjs";
import { type ContractCase, unfrozenPath } from "#/testing/slots/shared.mjs";

export interface FederationSettingsContractInput {
	/** The settings under test: what core fills the slot with, from the configuration its test chose. */
	readonly build: () => FederationSettings;
}

/** Every member an entry may carry: what core reads of it. */
const MEMBERS: ReadonlySet<string> = new Set<keyof ConfiguredFederation>([
	"type",
	"enabled",
	"trustsUpstreamAmr",
	"callbackMeetsFreshness",
	"callbackURL",
	"issuer",
	"clientId",
]);

/** The members read as written, each a non-empty string where present. */
const WRITTEN = ["callbackURL", "issuer", "clientId"] as const;

/** The entries of `settings` with each entry's members, read as own properties. */
const entriesOf = (
	settings: FederationSettings,
): readonly (readonly [string, Readonly<Record<string, unknown>>])[] =>
	Object.entries(settings) as unknown as readonly (readonly [
		string,
		Readonly<Record<string, unknown>>,
	])[];

/** The cases of the `federationSettings` contract over the settings `input` builds. */
export function federationSettingsContract(
	input: FederationSettingsContractInput,
): readonly ContractCase[] {
	const { build } = input;
	return [
		{
			name: "every entry names its type",
			run: async () => {
				for (const [name, entry] of entriesOf(build())) {
					assert.ok(
						typeof entry.type === "string" && /\S/.test(entry.type),
						`${name}.type is not a non-blank string: every core.federations entry names the federationTypes key that handles it`,
					);
				}
			},
		},
		{
			name: "enabled and trustsUpstreamAmr are booleans, and an upstream amr counts only for an enabled entry",
			run: async () => {
				for (const [name, entry] of entriesOf(build())) {
					assert.ok(
						typeof entry.enabled === "boolean",
						`${name}.enabled is not a boolean: absence is false, never undefined`,
					);
					assert.ok(
						typeof entry.trustsUpstreamAmr === "boolean",
						`${name}.trustsUpstreamAmr is not a boolean: absence is false, never undefined`,
					);
					assert.ok(
						entry.enabled === true || entry.trustsUpstreamAmr === false,
						`${name}.trustsUpstreamAmr is true beside a disabled entry: a disabled federation signs nobody in, so its upstream amr counts for nothing`,
					);
				}
			},
		},
		{
			name: "callbackMeetsFreshness is a boolean, true only for an enabled entry",
			run: async () => {
				for (const [name, entry] of entriesOf(build())) {
					assert.ok(
						typeof entry.callbackMeetsFreshness === "boolean",
						`${name}.callbackMeetsFreshness is not a boolean: absence reads as core's default, never undefined`,
					);
					assert.ok(
						entry.enabled === true || entry.callbackMeetsFreshness === false,
						`${name}.callbackMeetsFreshness is true beside a disabled entry: a disabled federation signs nobody in`,
					);
				}
			},
		},
		{
			name: "callbackURL, issuer and clientId are non-empty strings where present, and an enabled entry has a callbackURL",
			run: async () => {
				for (const [name, entry] of entriesOf(build())) {
					for (const member of WRITTEN) {
						if (!Object.hasOwn(entry, member)) continue;
						const value = entry[member];
						assert.ok(
							typeof value === "string" && value.length > 0,
							`${name}.${member} is present but not a non-empty string: one not written is absent`,
						);
					}
					if (entry.enabled === true) {
						assert.ok(
							Object.hasOwn(entry, "callbackURL"),
							`${name} is enabled without a callbackURL: boot refuses an enabled entry without one`,
						);
					}
				}
			},
		},
		{
			name: "an entry carries only what core reads of it",
			run: async () => {
				for (const [name, entry] of entriesOf(build())) {
					const other = Object.keys(entry).filter((member) => !MEMBERS.has(member));
					assert.deepEqual(
						other,
						[],
						`${name} carries ${other.join(", ")}: the rest of an entry, its secrets above all, is its type's module's, never core's view of it`,
					);
				}
			},
		},
		{
			name: "the settings inherit no member",
			run: async () => {
				assert.equal(
					Object.getPrototypeOf(build()),
					null,
					"the settings have a prototype: a name no entry has, such as constructor, would read as an entry",
				);
			},
		},
		{
			name: "the settings are frozen",
			run: async () => {
				const found = unfrozenPath(build(), "the settings");
				assert.equal(
					found,
					undefined,
					`${found} is not frozen: a module that reads the settings could change them under the others`,
				);
			},
		},
	];
}
