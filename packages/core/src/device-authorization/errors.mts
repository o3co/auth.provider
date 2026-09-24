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
 * - `"full"` — `create` found the store at its cap with every resident
 *   record live (#445). A bounded adapter throws this instead of evicting: a
 *   pending or approved-not-yet-polled record is a human's answer in flight,
 *   which nothing can reconstruct, whereas the request being refused can
 *   simply be made again. The device authorization endpoint answers it
 *   without re-drawing a code, because the store refused the slot, not the
 *   code.
 * - `"collision"` — `create` found a live record under the device code or the
 *   user code it was handed. A generator failure, not traffic: the device
 *   authorization endpoint re-draws both codes for this reason and for no
 *   other. Every other error a store throws is an outage, answered
 *   `503 temporarily_unavailable` without a retry — re-drawing cannot reach
 *   a store that is down, so the collision has to be told apart, and an
 *   adapter MUST signal it with this reason.
 */
export type DeviceCodeStoreErrorReason = "full" | "collision";

/**
 * Single discriminated-reason error class for `DeviceCodeStore` adapters.
 * Mirrors `ChallengeStorageError` / `RefreshTokenStorageError` discipline
 * (one class, discriminated reason, no per-reason subclasses), so a caller
 * that must tell one refusal from another switches on a field rather than
 * on a message.
 */
export class DeviceCodeStoreError extends Error {
	readonly reason: DeviceCodeStoreErrorReason;

	constructor(opts: { reason: DeviceCodeStoreErrorReason; message?: string; cause?: unknown }) {
		// Conditional super-arg so absent `cause` does not materialise an
		// own-property `cause` on the instance — the idiom `BootError` and
		// `ChallengeStorageError` share.
		super(
			opts.message ?? `DeviceCodeStoreError: ${opts.reason}`,
			opts.cause !== undefined ? { cause: opts.cause } : undefined,
		);
		this.name = "DeviceCodeStoreError";
		this.reason = opts.reason;
	}
}
