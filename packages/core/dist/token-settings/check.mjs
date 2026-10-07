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
 * Checks the `oauthTokenSettings` a composition holds before a reader reads
 * a member.
 *
 * Readers take every member from the slot when there is one, and from the
 * configuration only when there is none; never member by member, which
 * would mix two sources in one reading. A member the slot lacks would then
 * read `undefined`, a quiet `false` for a switch, so each member read is
 * held to its contract rule (the test kit's `oauthTokenSettingsContract`)
 * and a missing or wrong one refuses, naming it. The oauth module's
 * provider always passes; this is for a slot a host fills by hand.
 */
import { isLifetimeSeconds, resolveAccessTokenLifetime, resolveRefreshTokenLifetime, } from "../config/application.schema.mjs";
import { MAX_DURATION_SECONDS } from "../config/durations.mjs";
import { describeValue } from "../errors/describe-value.mjs";
import { checkCanonicalIssuer, describeIssuerRejection } from "../issuer/canonical.mjs";
const WHY = "A reader reads every member from the oauthTokenSettings a composition holds, and the " +
    "configuration only when it holds none, so a member the slot lacks or gets wrong is refused " +
    "rather than taken from the configuration beside it.";
/** The value a refusal names: `none` for a member the slot lacks, otherwise its kind. */
const shown = (value) => (value === undefined ? "none" : describeValue(value));
const refuse = (member, rule, value) => {
    throw new RangeError(`oauthTokenSettings.${member} ${rule}, and the composition's slot carries ${shown(value)}. ${WHY}`);
};
const SWITCHES = ["resourceIndicatorEnabled", "requireEmailVerified"];
/** A read of a slot's member that answers `undefined` rather than throwing. */
const readMember = (read) => {
    try {
        return read();
    }
    catch {
        return undefined;
    }
};
/**
 * The first token lifetime `settings` names beyond the one core resolves
 * from `config` (access-token max, then refresh-token), or `undefined`. A
 * non-number member is not compared; one whose read throws counts as none.
 * Each configured lifetime sizes a revoking record kept by a reader that
 * cannot read the slot: the access-token maximum, how long the refresh-token
 * family modules remember a revoked family (a family's own expiry follows the
 * slot); the refresh-token lifetime, how long the session lifecycle keeps a
 * closing session's record. A longer slot lifetime would mint a token that
 * outlives that record.
 * The resolver refuses a configuration that resolves no lifetime, naming
 * the key. Internal to core.
 */
export function lifetimeBeyondConfiguration(settings, config) {
    const slot = settings;
    const members = [
        {
            member: "accessTokenLifetime.maxExpiresIn",
            configKey: "oauth.accessToken.maxExpiresIn",
            slotSeconds: readMember(() => slot.accessTokenLifetime?.maxExpiresIn),
            configured: () => resolveAccessTokenLifetime(config).maxExpiresIn,
        },
        {
            member: "refreshTokenExpiresIn",
            configKey: "oauth.refreshToken.expiresIn",
            slotSeconds: readMember(() => slot.refreshTokenExpiresIn),
            configured: () => resolveRefreshTokenLifetime(config),
        },
    ];
    for (const { member, configKey, slotSeconds, configured } of members) {
        if (typeof slotSeconds !== "number")
            continue;
        const configurationSeconds = configured();
        if (slotSeconds > configurationSeconds) {
            return { member, configKey, slotSeconds, configurationSeconds };
        }
    }
    return undefined;
}
/**
 * Why each member is bounded by the configuration: the reader that sizes a
 * revoking record from the configured lifetime, and reads it from the
 * configuration because it cannot read the slot.
 */
const WHY_BOUNDED = {
    "accessTokenLifetime.maxExpiresIn": "The refresh-token family modules remember a revoked family for at least the configured " +
        "access-token maximum, read from the configuration, not the slot, so an access token minted " +
        "on the slot's maximum would outlive the record that revokes its family.",
    refreshTokenExpiresIn: "The session lifecycle keeps a closing session's record for the configured refresh-token " +
        "lifetime, read from the configuration, not the slot, so a refresh token minted on the " +
        "slot's lifetime would outlive the closing record that revokes it.",
};
/**
 * The refusal of a lifetime beyond the configuration's: the member, both
 * values, the configuration key, and why. `from` names where the slot came
 * from, when the caller knows.
 */
export function lifetimeBeyondConfigurationMessage(found, from) {
    return (`oauthTokenSettings.${found.member} is ${found.slotSeconds} s` +
        `${from === undefined ? "" : ` in the slot from ${from}`}, longer than the ` +
        `${found.configurationSeconds} s core resolves from the configuration (${found.configKey}). ` +
        `${WHY_BOUNDED[found.member]} Lower the slot's lifetime to the configuration's or below, ` +
        "or raise the configuration's.");
}
/**
 * A member of a host's value, read once. A read that throws — a getter, a
 * proxy trap — is refused, naming the member, rather than answered.
 */
const readOnce = (member, read) => {
    try {
        return read();
    }
    catch (err) {
        throw new RangeError(`oauthTokenSettings.${member} could not be read: reading it threw. ${WHY}`, { cause: err });
    }
};
export function checkOAuthTokenSettings(value, ...configuration) {
    const snapshot = settingsSnapshot(value);
    if (configuration.length === 0)
        return snapshot;
    const beyond = lifetimeBeyondConfiguration(snapshot, configuration[0]);
    if (beyond !== undefined)
        throw new RangeError(lifetimeBeyondConfigurationMessage(beyond));
    return snapshot;
}
/** The slot held to its contract rule, as a snapshot frozen at every level. */
function settingsSnapshot(value) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new RangeError(`oauthTokenSettings must be the settings object its contract describes, and the composition's slot holds ${shown(value)}. ${WHY}`);
    }
    const slot = value;
    const issuer = readOnce("issuer", () => slot.issuer);
    const lifetime = readOnce("accessTokenLifetime", () => slot.accessTokenLifetime);
    const lifetimeMembers = typeof lifetime === "object" && lifetime !== null
        ? lifetime
        : undefined;
    const defaultExpiresIn = lifetimeMembers === undefined
        ? undefined
        : readOnce("accessTokenLifetime.defaultExpiresIn", () => lifetimeMembers.defaultExpiresIn);
    const maxExpiresIn = lifetimeMembers === undefined
        ? undefined
        : readOnce("accessTokenLifetime.maxExpiresIn", () => lifetimeMembers.maxExpiresIn);
    const refreshTokenExpiresIn = readOnce("refreshTokenExpiresIn", () => slot.refreshTokenExpiresIn);
    const switches = new Map(SWITCHES.map((name) => [name, readOnce(name, () => slot[name])]));
    const rejection = checkCanonicalIssuer(issuer);
    if (rejection !== null)
        refuse("issuer", describeIssuerRejection(rejection), issuer);
    if (!isLifetimeSeconds(defaultExpiresIn) ||
        !isLifetimeSeconds(maxExpiresIn) ||
        defaultExpiresIn > maxExpiresIn) {
        return refuse("accessTokenLifetime", `must be a default and a max, each a whole number of seconds from 1 to ${MAX_DURATION_SECONDS}, the default not above the max`, lifetime);
    }
    if (!isLifetimeSeconds(refreshTokenExpiresIn)) {
        return refuse("refreshTokenExpiresIn", `must be a whole number of seconds from 1 to ${MAX_DURATION_SECONDS}`, refreshTokenExpiresIn);
    }
    for (const [name, read] of switches) {
        if (typeof read !== "boolean")
            refuse(name, "must be true or false", read);
    }
    return Object.freeze({
        issuer: issuer,
        accessTokenLifetime: Object.freeze({ defaultExpiresIn, maxExpiresIn }),
        refreshTokenExpiresIn,
        resourceIndicatorEnabled: switches.get("resourceIndicatorEnabled"),
        requireEmailVerified: switches.get("requireEmailVerified"),
    });
}
