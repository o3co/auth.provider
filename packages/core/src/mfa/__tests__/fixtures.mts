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
 * Internal-only test fixtures for MFA provider/coordinator/transaction store.
 * Not re-exported from the package root, not shipped in `dist` (tsconfig
 * excludes `__tests__/`). External provider authors should implement
 * `MfaProviderBase` directly per its TSDoc contract.
 */
import type {
	MfaChallenge,
	MfaIssueContext,
	MfaPendingTransaction,
	MfaProviderBase,
	MfaTransactionStore,
	MfaVerifyResult,
	SupportsEnrollment,
	SupportsRevocation,
} from "../types.mjs";

export function createTestMfaProvider(options: {
	kind: string;
	onIssue?: (userId: string, ctx: MfaIssueContext) => Promise<MfaChallenge | null>;
	onVerify?: (challengeId: string, proof: unknown) => Promise<MfaVerifyResult>;
}): MfaProviderBase {
	return {
		kind: options.kind,
		async issue(userId, ctx) {
			return options.onIssue
				? options.onIssue(userId, ctx)
				: {
						id: `${options.kind}-challenge-${userId}`,
						kind: options.kind,
						expiresAt: new Date(Date.now() + 5 * 60 * 1000),
					};
		},
		async verify(challengeId, proof) {
			return options.onVerify
				? options.onVerify(challengeId, proof)
				: { success: false, failureReason: "invalid" };
		},
	};
}

export function createTestMfaProviderWithCapabilities(options: {
	kind: string;
	onEnroll?: (
		userId: string,
		request: unknown,
	) => Promise<{ success: boolean; enrollmentId?: string }>;
	onRevoke?: (userId: string) => Promise<void>;
}): MfaProviderBase & SupportsEnrollment & SupportsRevocation {
	const base = createTestMfaProvider({ kind: options.kind });
	return {
		...base,
		async enroll(userId, request) {
			return options.onEnroll
				? options.onEnroll(userId, request)
				: { success: true, enrollmentId: `${options.kind}-${userId}` };
		},
		async revoke(userId) {
			if (options.onRevoke) await options.onRevoke(userId);
		},
	};
}

export function createInMemoryTransactionStore(): MfaTransactionStore {
	const store = new Map<string, MfaPendingTransaction>();
	return {
		async set(tx) {
			store.set(tx.transactionId, tx);
		},
		async get(transactionId) {
			const tx = store.get(transactionId);
			if (!tx) return null;
			if (tx.expiresAt.getTime() <= Date.now()) return null;
			return tx;
		},
		async delete(transactionId) {
			store.delete(transactionId);
		},
	};
}
