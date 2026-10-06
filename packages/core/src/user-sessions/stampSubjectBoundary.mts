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
 * How a subject revocation stamps its boundary: so that it covers everything
 * minted before the write took effect, not only what was minted before the
 * stamp time was read.
 */

/** One boundary write: `revokeBefore`, or `revokeSessionsBefore`, bound to its subject. */
export type BoundaryWrite = (before: Date, expiresAt: Date) => Promise<void>;

/**
 * How long a write may take to commit and still settle the boundary: well
 * inside the one-second allowance verification grants past it, so a token
 * minted while that write was in flight is covered by the instant it carries.
 */
const SETTLED_WRITE_MS = 250;

/** The most writes one stamping makes. */
const MAX_STAMPS = 4;

/** What {@link stampSubjectBoundary} did. */
export interface BoundaryStamp {
	/** Whether any write took effect: a boundary is in force. */
	readonly written: boolean;
	/**
	 * Why the boundary may not cover the in-flight issuance, if it may not:
	 * the first write threw (`1`), or a later one threw or none settled (`2`).
	 */
	readonly failure?: { readonly error: unknown; readonly stamp: 1 | 2 };
}

/**
 * Writes the boundary at `now()`, and once that write has taken effect,
 * writes it again at a fresh `now()`, each lasting `ttlMs`; then again while
 * the last write took longer than {@link SETTLED_WRITE_MS} to commit, up to
 * {@link MAX_STAMPS} writes in all.
 *
 * A write that commits late carries the instant read before it, and a token
 * minted between that instant and the commit would postdate it. Each later
 * stamp is read after the previous commit, so it reaches past it, and one
 * whose write settled covers what was minted while it was in flight. A store
 * keeps the later of two boundaries (the port's rule), so no stamp moves the
 * boundary back, even on a clock that stepped back. The second is tried even
 * when the first throws: a write can fail after it committed.
 */
export async function stampSubjectBoundary(
	write: BoundaryWrite,
	now: () => number,
	ttlMs: number,
): Promise<BoundaryStamp> {
	/** Writes one stamp; answers whether it committed within the bound. */
	const stamp = async (): Promise<boolean> => {
		const at = now();
		await write(new Date(at), new Date(at + ttlMs));
		return now() - at <= SETTLED_WRITE_MS;
	};
	let firstError: { readonly error: unknown } | undefined;
	try {
		await stamp();
	} catch (error) {
		firstError = { error };
	}
	for (let stamps = 2; stamps <= MAX_STAMPS; stamps += 1) {
		let settled: boolean;
		try {
			settled = await stamp();
		} catch (error) {
			return { written: firstError === undefined || stamps > 2, failure: { error, stamp: 2 } };
		}
		if (settled) {
			return firstError === undefined
				? { written: true }
				: { written: true, failure: { error: firstError.error, stamp: 1 } };
		}
	}
	return {
		written: true,
		failure: {
			error: new Error(
				`the subject boundary was written ${MAX_STAMPS} times and no write committed within ${SETTLED_WRITE_MS} ms`,
			),
			stamp: 2,
		},
	};
}
