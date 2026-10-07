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
 * How long a revoked refresh-token family's record is kept.
 *
 * `isFamilyRevoked` answers from the record, and answers "not revoked" when
 * there is none — so a revocation lasts exactly as long as its record. The
 * record's expiry is the family's (`RefreshTokenFamily.expiresAtMs`, the
 * refresh-token lifetime set once at creation), and revocation used to keep
 * it. That is long enough for the family's refresh tokens, whose `exp` it
 * caps, and not for its access tokens: an access token minted by a refresh
 * late in the family's life outlives the family by up to its own lifetime,
 * and the verifier accepts a token for `DEFAULT_CLOCK_SKEW_MS` past its `exp`
 * besides. When the revoked record went, those tokens passed the family check
 * again — at token exchange, userinfo and introspection — for the rest of
 * their life.
 *
 * So a revoked record is kept until the later of the family's own expiry and
 * the moment the last access token it could have minted stops being accepted:
 * now, plus the longest access-token lifetime the configuration allows (the
 * MAXIMUM, which token exchange may mint up to; an exchanged token inherits
 * its subject's `family_id`), plus `REVOCATION_RETENTION_ALLOWANCE_MS` — the
 * verifier's tolerance, the replica allowance the subject watermark uses and
 * a second of rounding, the same allowance a denylist entry gets. The same
 * sizing as `resolveSubjectRevocationHorizonMs` in
 * `user-sessions/retention.mts`, for the same reason: a revocation boundary
 * that expires while what it revoked is still accepted is not one.
 *
 * The allowance also bounds a race: the check-then-mint window. A grant finds
 * the family live — a token exchange's family check, a refresh's rotation —
 * and then mints. If the revocation commits in between, the token's `exp` is
 * measured from the grant's now, not the revocation's. The verifier's
 * tolerance is spent on that token's own `exp`, so what covers the gap is
 * `DEFAULT_SUBJECT_REVOCATION_SKEW_MS` plus the rounding second. The record
 * still outlives a token minted up to about two seconds after the
 * revocation committed. A grant slower than that between its check and its
 * mint leaves its token accepted past the record, by the difference.
 *
 * What this cannot know is what was issued before an operator lowered the
 * access-token maximum; a deployment that lowers it keeps revoked families
 * for the old one only as long as the old tokens could live. Nor can it
 * survive the memory store's process restart, which forgets every family —
 * revoked ones included — and is why that store is single-replica only.
 */
import { resolveAccessTokenLifetime, } from "../config/application.schema.mjs";
import { REVOCATION_RETENTION_ALLOWANCE_MS } from "../jwt/verify.mjs";
/**
 * The longest an access token carrying a family's `family_id` can live, in
 * milliseconds: `oauth.accessToken.maxExpiresIn`, read through
 * `resolveAccessTokenLifetime`, which refuses a configuration that has no
 * lifetime rather than letting a horizon be computed from nothing.
 */
export function resolveFamilyAccessTokenHorizonMs(config) {
    return resolveAccessTokenLifetime(config).maxExpiresIn * 1000;
}
/**
 * The expiry to commit for a family being revoked at `nowMs`: the later of
 * its own expiry and `nowMs + accessTokenHorizonMs`, plus
 * `REVOCATION_RETENTION_ALLOWANCE_MS` — rounded up to a whole millisecond,
 * since the Redis adapter writes it as `PX` and reads a stored family's
 * `expiresAtMs` back only as an integer.
 */
export function revokedFamilyExpiresAtMs(family, nowMs, accessTokenHorizonMs) {
    return Math.ceil(Math.max(family.expiresAtMs, nowMs + accessTokenHorizonMs) + REVOCATION_RETENTION_ALLOWANCE_MS);
}
/**
 * The `accessTokenHorizonMs` a wrapper was handed, or a construction error
 * naming it: a horizon that is not a positive lifetime would keep a revoked
 * record no longer than before.
 */
export function assertAccessTokenHorizonMs(value, factory) {
    if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
        throw new RangeError(`${factory}: accessTokenHorizonMs must be a positive number of milliseconds, and was ` +
            `${String(value)}. Size it with resolveFamilyAccessTokenHorizonMs(config): a revoked ` +
            "family's record must outlive the access tokens it revoked.");
    }
    return value;
}
