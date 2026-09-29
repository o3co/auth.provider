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
 * `isFamilyRevoked` answers "not revoked" when there is no record, so a
 * revocation lasts exactly as long as its record. The family's own expiry
 * covers its refresh tokens but not its access tokens: one minted late in the
 * family's life outlives it by up to its own lifetime, plus the verifier's
 * `DEFAULT_CLOCK_SKEW_MS`, and would pass the family check again (token
 * exchange, userinfo, introspection) once the record was gone.
 *
 * So a revoked record is kept until the later of the family's expiry and now
 * plus the maximum access-token lifetime (token exchange may mint up to it,
 * and an exchanged token inherits `family_id`), plus
 * `REVOCATION_RETENTION_ALLOWANCE_MS`. The same sizing as
 * `resolveSubjectRevocationHorizonMs` (`user-sessions/retention.mts`): a
 * revocation boundary that expires while what it revoked is still accepted is
 * not one.
 *
 * The allowance also covers the check-then-mint race (a grant finds the family
 * live, the revocation commits, the grant mints) for about two seconds
 * (`DEFAULT_SUBJECT_REVOCATION_SKEW_MS` plus a rounding second); a slower grant
 * leaves its token accepted past the record by the difference. Not covered:
 * tokens issued before the access-token maximum was lowered, and the memory
 * store's restart, which forgets every family (hence single-replica only).
 */

import {
	type AccessTokenLifetimeSource,
	resolveAccessTokenLifetime,
} from "../config/application.schema.mjs";
import { REVOCATION_RETENTION_ALLOWANCE_MS } from "../jwt/verify.mjs";
import type { RefreshTokenFamily } from "./types.mjs";

/**
 * The longest an access token carrying a family's `family_id` can live, in
 * milliseconds: `oauth.accessToken.maxExpiresIn`, read through
 * `resolveAccessTokenLifetime`, which refuses a configuration that has no
 * lifetime rather than letting a horizon be computed from nothing.
 */
export function resolveFamilyAccessTokenHorizonMs(config: unknown): number {
	return resolveAccessTokenLifetime(config as AccessTokenLifetimeSource).maxExpiresIn * 1000;
}

/**
 * The expiry to commit for a family being revoked at `nowMs`: the later of
 * its own expiry and `nowMs + accessTokenHorizonMs`, plus
 * `REVOCATION_RETENTION_ALLOWANCE_MS` — rounded up to a whole millisecond,
 * since the Redis adapter writes it as `PX` and reads a stored family's
 * `expiresAtMs` back only as an integer.
 */
export function revokedFamilyExpiresAtMs(
	family: Pick<RefreshTokenFamily, "expiresAtMs">,
	nowMs: number,
	accessTokenHorizonMs: number,
): number {
	return Math.ceil(
		Math.max(family.expiresAtMs, nowMs + accessTokenHorizonMs) + REVOCATION_RETENTION_ALLOWANCE_MS,
	);
}

/**
 * The `accessTokenHorizonMs` a wrapper was handed, or a construction error
 * naming it: a horizon that is not a positive lifetime would keep a revoked
 * record only until the family's own expiry.
 */
export function assertAccessTokenHorizonMs(value: unknown, factory: string): number {
	if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
		throw new RangeError(
			`${factory}: accessTokenHorizonMs must be a positive number of milliseconds, and was ` +
				`${String(value)}. Size it with resolveFamilyAccessTokenHorizonMs(config): a revoked ` +
				"family's record must outlive the access tokens it revoked.",
		);
	}
	return value;
}
