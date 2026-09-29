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
 * Why a `DeviceCodeStore` refused an operation.
 *
 * - `"full"` — `create` found the store at its cap with every record live.
 *   A bounded adapter throws this instead of evicting: a pending or
 *   approved-not-yet-polled record is a human's answer in flight and cannot
 *   be reconstructed, while the refused request can simply be retried. The
 *   endpoint does not re-draw a code for it.
 * - `"collision"` — `create` found a live record under the device code or
 *   the user code. The endpoint re-draws both codes for this reason only;
 *   any other store error is an outage (`503 temporarily_unavailable`, no
 *   retry), so an adapter MUST signal a collision with this reason.
 */
export type DeviceCodeStoreErrorReason = "full" | "collision";

/**
 * Error class for `DeviceCodeStore` adapters: one class with a
 * discriminated `reason`, like `ChallengeStorageError`, so callers switch on
 * a field rather than a message.
 */
export class DeviceCodeStoreError extends Error {
	readonly reason: DeviceCodeStoreErrorReason;

	constructor(opts: { reason: DeviceCodeStoreErrorReason; message?: string; cause?: unknown }) {
		// Pass options only when `cause` is set, so no own `cause: undefined`
		// property appears on the instance.
		super(
			opts.message ?? `DeviceCodeStoreError: ${opts.reason}`,
			opts.cause !== undefined ? { cause: opts.cause } : undefined,
		);
		this.name = "DeviceCodeStoreError";
		this.reason = opts.reason;
	}
}
