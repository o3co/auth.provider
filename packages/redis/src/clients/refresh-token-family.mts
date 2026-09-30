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
 * The refresh-token family store's client: a WATCH/MULTI/EXEC compare-and-set, on a connection
 * of its own that `duplicate()` opens and disposal closes.
 */

// --- RefreshTokenFamilyClient ----------------------------------------------

/**
 * Chainable transaction pipeline returned by `RefreshTokenFamilyClient.multi()`.
 */
export interface RefreshTokenFamilyMultiClient {
	set(key: string, value: string, mode: "PX", ttlMs: number): RefreshTokenFamilyMultiClient;
	/**
	 * Execute the queued commands. Same contract as
	 * {@link SessionSidSortedSetMultiClient.exec}: MUST reject when any queued
	 * command failed; `null` is the WATCH-abort signal, which the CAS loop
	 * reads as "conflict, retry".
	 */
	exec(): Promise<unknown[] | null>;
}

/**
 * Backing client for RefreshTokenFamilyStore adapters. The `duplicate()` method
 * returns a `DisposableRefreshTokenFamilyClient` bound to a new underlying
 * connection, required for WATCH/MULTI/EXEC CAS isolation.
 */
export interface RefreshTokenFamilyClient {
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	get(key: string): Promise<string | null>;
	pttl(key: string): Promise<number>;
	watch(...keys: string[]): Promise<"OK">;
	unwatch(): Promise<"OK">;
	multi(): RefreshTokenFamilyMultiClient;
	duplicate(): DisposableRefreshTokenFamilyClient;
}

/**
 * A `RefreshTokenFamilyClient` that owns a single network connection and is
 * responsible for closing it. Returned by `RefreshTokenFamilyClient.duplicate()`
 * so consumer code can use `await using conn = client.duplicate()` for scoped,
 * exception-safe connection lifetime.
 */
export interface DisposableRefreshTokenFamilyClient
	extends RefreshTokenFamilyClient,
		AsyncDisposable {
	[Symbol.asyncDispose](): Promise<void>;
}
