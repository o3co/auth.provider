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
/** A store's outage at `step`. */
export const outage = (store, step, cause) => ({
    outcome: "unavailable",
    store,
    step,
    cause,
});
/** Why a store's answer outside its port's promise is an outage: it is never read as a verdict. */
export const OUTSIDE_CONTRACT = new TypeError("the store answered outside its port's contract");
/** No usable transaction: unknown, foreign, spent, expired, or not a login's. */
export const UNKNOWN_TRANSACTION = Object.freeze({ outcome: "unknown_transaction" });
/** No factor of the subject's that an installed factor verifies, by the id named. */
export const UNKNOWN_FACTOR = Object.freeze({ outcome: "unknown_factor" });
