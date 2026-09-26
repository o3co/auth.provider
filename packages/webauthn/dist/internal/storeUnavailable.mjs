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
 * How this package answers a store that cannot answer, shared by the grant and
 * the three ceremony routes: `503 temporarily_unavailable`, with a description
 * naming the kind of store, and one error line carrying the error's
 * projection — never the error, which can carry what the store was sent. The
 * routes log it here as `webauthn_ceremony_store_unavailable`; the grant logs
 * its own `webauthn_grant_store_unavailable` and uses the descriptions.
 * Internal to the package.
 */
import { loggableError } from "@o3co/auth-provider-core";
const DESCRIPTIONS = {
    webauthn_credential: "credential store unavailable",
    challenge: "challenge store unavailable",
    // The ceremony is the challenge store and the replay seen-set together; to
    // the client both are where its challenge lives.
    challenge_ceremony: "challenge store unavailable",
    refresh_token_family: "refresh token store unavailable",
};
/** The `error_description` a 503 for `store` carries. */
export const storeUnavailableDescription = (store) => DESCRIPTIONS[store];
/**
 * Answer a ceremony route's store outage: one error line,
 * `webauthn_ceremony_store_unavailable`, then `503 temporarily_unavailable`.
 */
export function refuseCeremonyStoreUnavailable(res, logger, failure, cause) {
    logger.error({ site: failure.site, store: failure.store, step: failure.step, err: loggableError(cause) }, "webauthn_ceremony_store_unavailable");
    res.status(503).json({
        error: "temporarily_unavailable",
        error_description: storeUnavailableDescription(failure.store),
    });
}
