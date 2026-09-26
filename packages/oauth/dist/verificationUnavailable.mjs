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
 * The one answer the routes here give a token they could not verify because
 * a dependency was down — the keystore, or a revocation store — as core's
 * `isVerificationUnavailable` reports it. (`/oauth/revoke` logs the same line
 * but words its 503 as RFC 7009 §2.2.1's retry, beside its other 503s; the
 * refresh grant answers through the token endpoint's envelope.)
 *
 * `503 temporarily_unavailable`, with core's description naming the
 * dependency, no `WWW-Authenticate` challenge, and an error-level
 * `token_verification_unavailable` line carrying the route (`site`), the
 * reason and the projected error — whose cause is what the dependency threw.
 * Never `401 invalid_token`, `active: false` or a silent `200`: each of those
 * is a verdict on the token, and an outage is not one (see
 * `isVerificationUnavailable` in core's `jwt/verify.mts`).
 */
import { loggableError, VERIFICATION_UNAVAILABLE_DESCRIPTION, } from "@o3co/auth-provider-core";
export function refuseVerificationUnavailable(res, err, logger, site) {
    logger?.error({ site, reason: err.reason, err: loggableError(err) }, "token_verification_unavailable");
    return res.status(503).json({
        error: "temporarily_unavailable",
        error_description: VERIFICATION_UNAVAILABLE_DESCRIPTION[err.reason],
    });
}
