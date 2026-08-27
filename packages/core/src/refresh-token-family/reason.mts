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
 * `RefreshTokenFamilyUpdateResult`, omitting the key entirely when the
 * decision carried none.
 *
 * ```ts
 * return { outcome: "aborted", ...withReason(decision.reason) };
 * ```
 *
 * Why this exists rather than `reason: decision.reason` at each call site:
 * `reason` is declared OPTIONAL, and an unconditional assignment puts the key
 * on the object holding `undefined`. "Absent" and "present but `undefined`"
 * are then indistinguishable to the contract but distinguishable to every
 * consumer — `"reason" in result`, `Object.keys`, `toStrictEqual`, and any
 * serialisation of the result all disagree with each other about which one
 * happened. An adapter that always writes the key silently contradicts the
 * interface it implements.
 *
 * Why it is EXPORTED rather than inlined twice: the in-memory and Redis
 * adapters must be substitutable down to the shape of what they return, which
 * is the premise that lets the rotation ceremony live in one shared wrapper
 * instead of being reimplemented per backend (A3 §5.1). Two hand-written
 * copies of the same conditional spread is exactly the kind of parity that
 * decays on the next edit, so both call it, and so should any third-party
 * `RefreshTokenFamilyStore`.
 *
 * Per A3 §5.1 + #274.
 */
export const withReason = (reason: string | undefined): { reason?: string } =>
	reason === undefined ? {} : { reason };
