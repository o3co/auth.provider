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
 * How long a subject's revocation boundary has to last (#593, D13).
 *
 * There are two boundaries and they are bounded by different things, which is
 * why there are two answers here rather than one number.
 *
 * The **grants** boundary must outlast every grant it could ever cover. What
 * bounds a grant is `FEDERATION_GRANT_LIFETIME_CEILING_MS`, which `activate`
 * enforces at the write — *not* `federationGrants.maxExpiresIn`, which an
 * operator can lower, revoke under, and raise again, resurrecting a grant the
 * revocation was meant to end. So the floor below is a constant derived from a
 * constant, and neither configuration nor a caller can shorten it.
 *
 * The **sessions** boundary must outlast the sessions and tokens a cascade
 * might have missed, and what bounds *those* is configuration — so that one is
 * resolved, not fixed.
 */
import { resolveAccessTokenLifetime, } from "../config/application.schema.mjs";
import { FEDERATION_GRANT_LIFETIME_CEILING_MS } from "../federation-grants/lifetime.mjs";
import { DEFAULT_CLOCK_SKEW_MS, DEFAULT_SUBJECT_REVOCATION_SKEW_MS } from "../jwt/verify.mjs";
/**
 * One minute more than the longest grant the code will ever allow.
 *
 * A grant's `expiresAt` is at most `consent.at` plus the ceiling (D3, enforced
 * by `activate`), and a boundary is stamped no earlier than the consent it
 * covers, give or take the comparison's second and the rounding to whole
 * seconds. Both are far inside the minute. So a boundary retained this long
 * outlives every grant it covers, whatever the operator does to the
 * configuration and whether or not the caller passed a grant store.
 *
 * The cost is one small key per revoked subject, for a year.
 */
export const SUBJECT_REVOCATION_MIN_RETENTION_MS = FEDERATION_GRANT_LIFETIME_CEILING_MS + 60_000;
/** Whole milliseconds an operator configured, or a refusal that names the path. */
const lifetime = (value, path, unit) => {
    const raw = typeof value === "number" ? value : Number.NaN;
    if (!Number.isFinite(raw) || raw <= 0) {
        throw new RangeError(`resolveSubjectRevocationHorizonMs: ${path} must be a positive number of ` +
            `${unit === "s" ? "seconds" : "milliseconds"}, and was ${JSON.stringify(value)}. ` +
            "The subject's revocation boundary is sized from it, and one computed from a " +
            "missing lifetime expires while the sessions it covers are still being accepted.");
    }
    return unit === "s" ? raw * 1000 : raw;
};
/**
 * How long a **sessions-only** boundary must be retained, from the lifetimes
 * this deployment is configured with.
 *
 * Three inputs, not two. D13 named the refresh token and the session; the
 * access token belongs here as well, because nothing in the configuration says
 * an access token must be shorter than a refresh token — a deployment is free
 * to invert them, and `verifyJwt` consults the watermark for both.
 *
 * And each is extended by the tolerance with which it is actually accepted,
 * not by its nominal expiry: `verifyJwt` passes `clockTolerance`, so a token is
 * acceptable for `DEFAULT_CLOCK_SKEW_MS` past its `exp`. A boundary sized to
 * the nominal expiry leaves exactly that window with nothing behind it. The
 * revocation comparison's own allowance and a whole second of rounding go on
 * top; neither is the five-minute tolerance, which is a different number for a
 * different comparison.
 *
 * What this cannot know is what was issued *before* an operator lowered these
 * settings. Lowering a lifetime shortens the horizon immediately while the
 * artifacts issued under the old one are still live, so a deployment that
 * lowers one keeps the previous horizon until they have expired. The grants
 * boundary has no such hole, because its floor comes from a ceiling the code
 * enforces rather than from configuration.
 */
export function resolveSubjectRevocationHorizonMs(config) {
    const root = config;
    const refreshMs = lifetime(root?.oauth?.refreshToken?.expiresIn, "oauth.refreshToken.expiresIn", "s");
    // The MAXIMUM, not the default. `oauth.accessToken.expiresIn` is what a
    // grant mints when the request asks for nothing; token exchange may ask
    // for more, up to `maxExpiresIn`. Sizing the horizon from the default
    // leaves exactly those longer tokens outliving the boundary that revoked
    // them — 60-second defaults beside a one-day maximum would retain the
    // boundary for six minutes. `resolveAccessTokenLifetime` is the one
    // correct reader of that pair, alias and all, and it refuses a value that
    // is not a lifetime rather than letting this compute from one.
    const accessMs = resolveAccessTokenLifetime(config).maxExpiresIn * 1000;
    const sessionMs = lifetime(root?.session?.maxAge, "session.maxAge", "ms");
    const longest = Math.max(sessionMs, refreshMs + DEFAULT_CLOCK_SKEW_MS, accessMs + DEFAULT_CLOCK_SKEW_MS);
    // The revocation comparison's own allowance, and one whole second for the
    // rounding a caller may have applied to the instant it stamped.
    return longest + DEFAULT_SUBJECT_REVOCATION_SKEW_MS + 1_000;
}
