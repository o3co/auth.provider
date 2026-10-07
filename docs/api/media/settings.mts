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
 * The `federationSettings` slot's type: core's view of `core.federations`,
 * which boot fills for every composition, so that a module reads the
 * federations a configuration declares from its dependencies, never from
 * `config`. What it holds of an entry is what core reads of it; an entry's
 * secrets and the rest of its type's keys stay with the type's module.
 */

/** What core reads of one `core.federations` entry, frozen. */
export interface ConfiguredFederation {
	/** The `federationTypes` key of the module that handles it, as the entry names it. */
	readonly type: string;
	/** Whether it is switched on: `enabled` is `true` as core's schema read it. */
	readonly enabled: boolean;
	/**
	 * Whether its upstream IdP's `amr` counts, as `federationTrustsUpstreamAmr`
	 * answers: `true` only beside `enabled`, when `trustUpstreamAmr` is `true`.
	 */
	readonly trustsUpstreamAmr: boolean;
	/**
	 * Whether its callback alone meets a freshness ask when the upstream shows
	 * no `auth_time`, as `federationCallbackMeetsFreshness` answers: `true`
	 * only beside `enabled`.
	 */
	readonly callbackMeetsFreshness: boolean;
	/**
	 * Where its upstream redirects back to, as written. Every enabled entry has
	 * one, since boot refuses one without; a disabled entry has one only when
	 * it writes a non-empty string.
	 */
	readonly callbackURL?: string;
	/**
	 * The upstream's issuer exactly as the entry writes it, when that is a
	 * non-empty string: a key of its type's, which core reads and never checks,
	 * for a reader that pins an upstream identity to what an operator can see.
	 */
	readonly issuer?: string;
	/** The client id at the upstream exactly as the entry writes it, when that is a non-empty string; read as `issuer` is. */
	readonly clientId?: string;
}

/**
 * Every `core.federations` entry by name, enabled or not, in the
 * configuration's key order: `{}` when it declares none. Deeply frozen, and
 * inheriting nothing, so a name no entry has — `constructor` included — reads
 * as absent.
 */
export type FederationSettings = Readonly<Record<string, ConfiguredFederation>>;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/**
		 * Core's view of `core.federations`: filled by boot from the
		 * configuration for every composition, before any provider runs. A
		 * synthetic key: no module provides it and no host map sets it
		 * (`synthetic-key-collision`).
		 */
		readonly federationSettings?: FederationSettings;
	}
}
