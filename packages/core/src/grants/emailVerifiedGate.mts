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
 * Whether a user's Store-published state says their email is verified (#297).
 *
 * `oauth.requireEmailVerified` turns this into a gate on token issuance for an
 * end-user subject. The verification *flow* stays where it belongs — the Store
 * issues the token, delivers it, and flips the state; this library only reads
 * the result and decides whether to issue.
 *
 * Accepts **exactly** `true`. Absence is not verification: a Store that does
 * not model the field has not verified anything, and a deployment that turned
 * the gate on is asking for a positive signal, not the absence of a negative
 * one. A truthy non-boolean is rejected for the same reason the claim filter
 * drops it — a Store is reached across an untyped boundary, and the string
 * `"false"` is truthy.
 */
export const isEmailVerified = (user: unknown): boolean =>
	typeof user === "object" &&
	user !== null &&
	(user as { emailVerified?: unknown }).emailVerified === true;
