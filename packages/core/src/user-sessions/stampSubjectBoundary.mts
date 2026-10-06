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
 * How long a write may take to commit and still settle the boundary, and how
 * far past the instant read before it the boundary is stamped. A token minted
 * before a settled write commits was minted before the boundary it carries,
 * so the verification allowance is left whole for the issuers' clock skew.
 */
const SETTLED_WRITE_MS = 250;

/** The most writes one stamping makes. */
const MAX_STAMPS = 4;

/** Whether a clock moved forward across a write by no more than {@link SETTLED_WRITE_MS}. */
const withinBound = (ms: number): boolean => ms >= 0 && ms <= SETTLED_WRITE_MS;

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
 * Writes the boundary at `now()` plus {@link SETTLED_WRITE_MS}, and once that
 * write has taken effect, writes it again from a fresh `now()`, each lasting
 * `ttlMs` past the boundary; then again while the last write did not settle,
 * up to {@link MAX_STAMPS} writes in all.
 *
 * A write settles when it commits within {@link SETTLED_WRITE_MS} on the
 * monotonic clock (`elapsed`) and the wall clock moved forward by no more
 * than that across it: a token minted before it committed then predates the
 * boundary it wrote. A store keeps the later of two boundaries (the port's
 * rule), so no stamp moves the boundary back, even on a clock that stepped
 * back. The second is tried even when the first throws: a write can fail
 * after it committed.
 */
export async function stampSubjectBoundary(
	write: BoundaryWrite,
	now: () => number,
	ttlMs: number,
	elapsed: () => number = () => performance.now(),
): Promise<BoundaryStamp> {
	/** Writes one stamp; answers whether it settled. */
	const stamp = async (): Promise<boolean> => {
		const at = now();
		const started = elapsed();
		const before = at + SETTLED_WRITE_MS;
		await write(new Date(before), new Date(before + ttlMs));
		return withinBound(elapsed() - started) && withinBound(now() - at);
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
				`no write of the subject boundary after the first settled within ${SETTLED_WRITE_MS} ms in ${MAX_STAMPS - 1} attempts`,
			),
			stamp: 2,
		},
	};
}
