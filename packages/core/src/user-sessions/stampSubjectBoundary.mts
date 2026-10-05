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

/** What {@link stampSubjectBoundary} did. */
export interface BoundaryStamp {
	/** Whether the first write took effect: a boundary is in force. */
	readonly written: boolean;
	/** The write that threw, if one did; then the boundary may not cover the commit. */
	readonly failure?: { readonly error: unknown };
}

/**
 * Writes the boundary at `now()`, and once that write has taken effect,
 * writes it again at a fresh `now()`, each lasting `ttlMs`.
 *
 * A write that commits late carries the instant read before it, and a token
 * minted between that instant and the commit would postdate it. The second
 * stamp is read after the commit, so it reaches past it. A store keeps the
 * later of two boundaries (the port's rule), so the second never moves the
 * boundary back, even on a clock that stepped back. When the first write
 * throws, the second is not tried.
 */
export async function stampSubjectBoundary(
	write: BoundaryWrite,
	now: () => number,
	ttlMs: number,
): Promise<BoundaryStamp> {
	const stamp = async (): Promise<void> => {
		const at = now();
		await write(new Date(at), new Date(at + ttlMs));
	};
	try {
		await stamp();
	} catch (error) {
		return { written: false, failure: { error } };
	}
	try {
		await stamp();
	} catch (error) {
		return { written: true, failure: { error } };
	}
	return { written: true };
}
