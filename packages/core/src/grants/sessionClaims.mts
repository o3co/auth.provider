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
 * - `sid`: the session the token was minted from (`authorization_code`,
 *   `refresh_token`, `session` grants). A liveness link (logout ends the
 *   token) and a capability: `/oauth/userinfo`, federation logout and the
 *   federation token route act on the session through it.
 * - `liveness_sid` ({@link LIVENESS_SID_CLAIM}): the session a token-exchange
 *   result was derived from. Liveness only; nothing is authorised on it,
 *   because a downstream holder is not the session's client.
 *
 * Two claims, not one claim plus a mark the capability routes refuse: every
 * surface reading `sid` is unreachable with an exchanged token, and only
 * liveness checks opt in to the second claim. A forgotten opt-in leaves a
 * token live after logout; a forgotten refusal would hand out the session's
 * capabilities.
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
