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
 * Internal test fixture: in-memory RefreshTokenStore with atomic rotate()
 * semantics. Not a production adapter (single-process only; no TTL eviction).
 */
import type { RefreshTokenRotateOutcome, RefreshTokenStoreBase } from "../types.mjs";

type TokenState = "active" | "consumed";

export function createInMemoryRefreshTokenStore(): RefreshTokenStoreBase {
	const tokens = new Map<string, { familyId: string; state: TokenState; expiresAt: number }>();
	const revokedFamilies = new Set<string>();
	const locks = new Map<string, Promise<void>>();

	async function withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
		const previous = locks.get(key) ?? Promise.resolve();
		let resolveOurLock!: () => void;
		const ourLock = new Promise<void>((r) => {
			resolveOurLock = r;
		});
		locks.set(
			key,
			previous.then(() => ourLock),
		);
		await previous;
		try {
			return await fn();
		} finally {
			resolveOurLock();
			if (locks.get(key) === ourLock) locks.delete(key);
		}
	}

	return {
		kind: "memory",
		async rotate(previousJti, newJti, familyId, expiresAt): Promise<RefreshTokenRotateOutcome> {
			return withLock(familyId, async () => {
				if (revokedFamilies.has(familyId)) {
					return { outcome: "revoked" };
				}
				if (previousJti === null) {
					tokens.set(newJti, { familyId, state: "active", expiresAt: expiresAt.getTime() });
					return { outcome: "rotated" };
				}
				const prev = tokens.get(previousJti);
				if (!prev) {
					tokens.set(newJti, { familyId, state: "active", expiresAt: expiresAt.getTime() });
					return { outcome: "unknown" };
				}
				if (prev.state === "consumed") {
					revokedFamilies.add(familyId);
					return { outcome: "replayed", familyId };
				}
				prev.state = "consumed";
				tokens.set(newJti, { familyId, state: "active", expiresAt: expiresAt.getTime() });
				return { outcome: "rotated" };
			});
		},
		async isFamilyRevoked(familyId) {
			return revokedFamilies.has(familyId);
		},
		async revokeFamily(familyId) {
			revokedFamilies.add(familyId);
		},
	};
}
