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
 * Spread the optional `reason` of a `RefreshTokenFamilyUpdateDecision` onto a
 * `RefreshTokenFamilyUpdateResult`, omitting the key when the decision carried
 * none.
 *
 * `reason` is optional: writing `reason: undefined` makes "absent" and
 * "present but `undefined`" diverge for `in`, `Object.keys`, `toStrictEqual`
 * and serialisation. Exported so every `RefreshTokenFamilyStore` adapter
 * (in-memory, Redis, third-party) returns the same shape, which the shared
 * rotation wrapper relies on.
 */
export const withReason = (reason: string | undefined): { reason?: string } =>
	reason === undefined ? {} : { reason };
