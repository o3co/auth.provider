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
 * The refresh back-off: after a refresh of a record answered `500
 * refresh_failed`, that record is not refreshed upstream again by this
 * process for a fixed window. A record is its session, its federation and its
 * access token, so a relink (a new access token) is never held back. Held in
 * process memory, so each replica holds back only its own refreshes; bounded
 * by a capacity past which the oldest stamp is dropped. Only a digest of the
 * access token is kept.
 */

import { createHash } from "node:crypto";

export const REFRESH_BACKOFF_WINDOW_MS = 30_000;
const REFRESH_BACKOFF_MAX_ENTRIES = 10_000;

export interface RefreshBackoffKey {
	readonly sid: string;
	readonly federationName: string;
	readonly accessToken: string;
}

export interface RefreshBackoff {
	/** Whether a stamp of this record, made at most the window before `now`, stands. */
	holds(key: RefreshBackoffKey, now: number): boolean;
	/** Stamps this record's refresh as failed at `now`. */
	stamp(key: RefreshBackoffKey, now: number): void;
}

export const createRefreshBackoff = (
	limits: { readonly windowMs: number; readonly maxEntries: number } = {
		windowMs: REFRESH_BACKOFF_WINDOW_MS,
		maxEntries: REFRESH_BACKOFF_MAX_ENTRIES,
	},
): RefreshBackoff => {
	// Insertion order is stamp order: a re-stamp is deleted and set again, so
	// the first entry is always the oldest.
	const stamps = new Map<string, { readonly digest: string; readonly at: number }>();
	const slot = (key: RefreshBackoffKey): string => JSON.stringify([key.sid, key.federationName]);
	const digest = (accessToken: string): string =>
		createHash("sha256").update(accessToken).digest("base64url");
	const stands = (at: number, now: number): boolean => now >= at && now - at < limits.windowMs;

	return {
		holds(key, now) {
			const stamp = stamps.get(slot(key));
			return (
				stamp !== undefined && stands(stamp.at, now) && stamp.digest === digest(key.accessToken)
			);
		},
		stamp(key, now) {
			const id = slot(key);
			stamps.delete(id);
			stamps.set(id, { digest: digest(key.accessToken), at: now });
			for (const [oldest, { at }] of stamps) {
				if (stamps.size <= limits.maxEntries && stands(at, now)) break;
				stamps.delete(oldest);
			}
		},
	};
};
