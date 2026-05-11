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

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";

export interface MfaChallenge {
	readonly id: string;
	readonly kind: string;
	/**
	 * Expiry encoding: `Date` per A4 two-tier design — see {@link UserSession}
	 * for rationale.
	 */
	readonly expiresAt: Date;
	readonly metadata?: Record<string, unknown>;
}

export interface MfaIssueContext {
	readonly request: { ip?: string; userAgent?: string };
}

export type MfaVerifyFailureReason = "invalid" | "expired" | "locked" | "unknown";

export interface MfaVerifyResult {
	readonly success: boolean;
	readonly failureReason?: MfaVerifyFailureReason;
}

/**
 * Adapter primitive for MFA challenge providers.
 */
export interface MfaProvider {
	readonly kind: string;
	issue(userId: string, ctx: MfaIssueContext): Promise<MfaChallenge | null>;
	verify(challengeId: string, proof: unknown): Promise<MfaVerifyResult>;
}

export interface EnrollResult {
	readonly success: boolean;
	readonly enrollmentId?: string;
	readonly metadata?: Record<string, unknown>;
}

export interface SupportsEnrollment {
	enroll(userId: string, request: unknown): Promise<EnrollResult>;
}

export interface SupportsRevocation {
	revoke(userId: string): Promise<void>;
}

export function supportsEnrollment(
	p: MfaProvider | undefined | null,
): p is MfaProvider & SupportsEnrollment {
	if (p == null) return false;
	return typeof (p as { enroll?: unknown }).enroll === "function";
}

export function supportsRevocation(
	p: MfaProvider | undefined | null,
): p is MfaProvider & SupportsRevocation {
	if (p == null) return false;
	return typeof (p as { revoke?: unknown }).revoke === "function";
}

export type MfaProviderFactory = AdapterFactory<MfaProvider>;

export type MfaResumeState =
	| {
			readonly flow: "authorize";
			readonly clientId: string;
			readonly redirectUri: string;
			readonly scope?: readonly string[];
			readonly state?: string;
			readonly codeChallenge?: string;
			readonly codeChallengeMethod?: string;
			readonly responseType: string;
	  }
	| {
			readonly flow: "federation";
			readonly providerName: string;
			readonly redirectTo?: string;
	  }
	| {
			readonly flow: "login";
			readonly redirectTo?: string;
	  };

export interface MfaPendingTransaction {
	readonly transactionId: string;
	readonly flow: "authorize" | "federation" | "login";
	readonly subject: string;
	readonly providerKind: string;
	readonly challengeId: string;
	/**
	 * Expiry encoding: `Date` per A4 two-tier design — see {@link UserSession}
	 * for rationale.
	 */
	readonly expiresAt: Date;
	readonly resumeState: MfaResumeState;
}

export interface MfaTransactionStore {
	/**
	 * Persist a pending MFA transaction.
	 *
	 * Renamed from `save` in v0.5.1 (AS-11) to align with map-like store
	 * semantics ({@link UserSessionStore}, {@link KeyStore}). The old `save` name is
	 * no longer accepted; the v0.5.1 hotfix policy explicitly permits this
	 * rename for an interface that was new in v0.5.0.
	 */
	set(tx: MfaPendingTransaction): Promise<void>;
	/**
	 * Retrieve a pending transaction by id. Implementations MAY filter expired
	 * transactions (return null when `expiresAt <= now`); core also rejects
	 * expired transactions after retrieval as defense in depth. Either
	 * behavior is acceptable.
	 *
	 * Renamed from `load` in v0.5.1 (AS-11) — see {@link MfaTransactionStore.set}.
	 */
	get(transactionId: string): Promise<MfaPendingTransaction | null>;
	delete(transactionId: string): Promise<void>;
}

export interface MfaCoordinator {
	listEnrolled(userId: string): Promise<readonly MfaProvider[]>;
}
