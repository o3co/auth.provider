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
 * Rejects a batch size that is not a positive integer, at construction:
 * `createRedisSidSet`'s `scanCount` is an `SSCAN` `COUNT` hint, and Redis
 * refuses a non-positive `COUNT`, which would surface during a logout.
 * `Number.isSafeInteger` also refuses `NaN`, both infinities and fractions.
 */
export function assertPositiveInteger(value: number, label: string): void {
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new Error(`${label} must be a positive integer (received ${String(value)})`);
	}
}
