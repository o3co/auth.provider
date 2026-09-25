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
 * The two ways an access token names the browser session behind it.
 *
 * - **`sid`** is the session a token was minted from, by the grant that holds
 *   it (`authorization_code`, `refresh_token`, `session`). It is a liveness
 *   link — a logout ends the `UserSession` and with it the token — and a
 *   capability: `/oauth/userinfo` releases the session's claims on it,
 *   `POST /oauth/federation/:name/logout` deletes the session's upstream tokens
 *   on it, and the federation token route hands the upstream access token out
 *   on it.
 * - **`liveness_sid`** ({@link LIVENESS_SID_CLAIM}) is the session a token was
 *   derived from without being minted from it — a token-exchange result. It is
 *   the liveness link alone: the logout that ends the subject token ends this
 *   one too, and nothing is authorised on it. A downstream holder of an
 *   exchanged token is not the session's client, so none of the session's
 *   capabilities may be reachable with it.
 *
 * Two claims rather than one claim and a mark that the capability routes
 * refuse: a surface that reads `sid` — every capability today and any added
 * later — can never be reached with an exchanged token, because it does not
 * carry one; only the liveness checks opt in to the second claim. A
 * forgotten opt-in leaves a token live after a logout, which is the state
 * before the link existed; a forgotten refusal would hand a session's
 * capabilities to whoever holds a derived token.
 */

/** The claim a derived token names its subject's session under — read by liveness checks only. */
export const LIVENESS_SID_CLAIM = "liveness_sid";

const nonEmptyString = (value: unknown): string | null =>
	typeof value === "string" && value.length > 0 ? value : null;

/**
 * The session a token's liveness depends on: its own `sid`, else its
 * `liveness_sid`; `null` when it names neither as a non-empty string. What
 * `/oauth/introspect` and `/oauth/userinfo` resolve against the
 * `UserSession` store, and what the token-exchange validator reports as
 * `ValidatedToken.sid`. Never what a session capability is authorised on —
 * that is `sid` alone.
 */
export const livenessSidOf = (claims: Readonly<Record<string, unknown>>): string | null =>
	nonEmptyString(claims.sid) ?? nonEmptyString(claims[LIVENESS_SID_CLAIM]);
