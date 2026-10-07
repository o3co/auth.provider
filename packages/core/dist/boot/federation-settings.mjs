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
 * boot/federation-settings.mts: what boot fills the `federationSettings`
 * slot with — core's view of `core.federations`, built from core's own
 * readings of it (`federationsOf`, `enabledFederationsOf`,
 * `federationTrustsUpstreamAmr`, `federationCallbackMeetsFreshness`) over the
 * configuration stage 1 parsed.
 */
import { enabledFederationsOf, federationsOf } from "../federations/configured.mjs";
import { federationCallbackMeetsFreshness, federationTrustsUpstreamAmr, } from "../user-sessions/authentication.mjs";
/** The keys an entry is read for as written, each kept only when it is a non-empty string. */
const WRITTEN_KEYS = ["callbackURL", "issuer", "clientId"];
/**
 * Every `core.federations` entry of `config`, by name in the map's order,
 * as `ConfiguredFederation`: its type, whether it is on, whether its
 * upstream `amr` counts, whether its callback alone meets a freshness ask, and `callbackURL`, `issuer` and `clientId` where
 * written as non-empty strings — nothing else of it, so no secret. The map
 * inherits nothing and is frozen with each entry. Reads the configuration
 * core's schema parsed, which holds every entry to an object naming its type
 * and coerces its switches.
 * @internal
 */
export function federationSettingsOf(config) {
    const enabled = new Set(enabledFederationsOf(config).map(([name]) => name));
    const settings = Object.create(null);
    for (const [name, entry] of Object.entries(federationsOf(config))) {
        const written = entry;
        const strings = Object.fromEntries(WRITTEN_KEYS.flatMap((key) => {
            const value = Object.hasOwn(written, key) ? written[key] : undefined;
            return typeof value === "string" && value.length > 0 ? [[key, value]] : [];
        }));
        settings[name] = Object.freeze({
            type: written.type,
            enabled: enabled.has(name),
            trustsUpstreamAmr: federationTrustsUpstreamAmr(config, name),
            callbackMeetsFreshness: federationCallbackMeetsFreshness(config, name),
            ...strings,
        });
    }
    return Object.freeze(settings);
}
