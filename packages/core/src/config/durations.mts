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
 * Sanity ceiling for a duration expressed in whole seconds: one year.
 *
 * Not a policy — a deployment wanting a 400-day refresh token is a different
 * conversation — but a typo guard. The pairing with `.positive()` is what
 * actually matters (see `readinessTimeoutMs` for the same reasoning): HOCON
 * substitutes an exported-but-empty environment variable as `""`, and
 * `z.coerce.number()` turns `""` into `0`. A zero token lifetime mints tokens
 * that are already expired.
 *
 * Exported so a package's own config schema holds its durations to the same
 * ceiling as core's: a rate-limit window, a federation grant's tombstone
 * retention or listing allowance. Past the Date range, such a value is a
 * deadline no store can keep (`isStorableLifetime`), and the store's refusal
 * at construction is the second line behind this one.
 */
export const MAX_DURATION_SECONDS = 31_536_000;

/** The same one-year ceiling for the settings expressed in milliseconds. */
export const MAX_DURATION_MS = 31_536_000_000;
