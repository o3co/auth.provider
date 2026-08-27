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

export interface AuditEvent {
	readonly timestamp: Date;
	/**
	 * Built-in event types (informative, not exhaustive):
	 *   "login.success" | "login.failure" |
	 *   "authorize.granted" | "authorize.rejected" |
	 *   "token.issued" | "token.issued.failure" | "token.refreshed" | "token.revoked" |
	 *   "federation.success" | "federation.failure" |
	 *   "mfa.challenge.issued" | "mfa.challenge.success" | "mfa.challenge.failure" |
	 *   "logout" | "scope.denied" | "rate_limit.unavailable"
	 * Consumers MAY emit custom event types with their own namespace.
	 */
	readonly type: string;
	readonly subject?: string;
	readonly clientId?: string;
	readonly ip?: string;
	readonly userAgent?: string;
	readonly details?: Record<string, unknown>;
}

/**
 * Adapter primitive for audit-event sinks.
 */
export interface AuditSink {
	readonly kind: string;
	/**
	 * Fire-and-forget recording. Implementations MAY buffer or batch internally.
	 * Errors thrown here are swallowed by auth.provider core (audit failure
	 * does NOT block auth flow).
	 */
	record(event: AuditEvent): Promise<void>;
}

export type AuditSinkFactory = AdapterFactory<AuditSink>;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge (A2-α §6.1 — optional slot)
//
// Declared here so oauthModule can list "auditSink" in its `optional` array
// and the DI graph types deps.auditSink as AuditSink | undefined.
// The slot is optional: when absent, oauth routes emit no audit events (the
// emitAuditEvent helper is a no-op when sink is undefined).
// Phase 9 Task 4 augmentation.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly auditSink?: AuditSink;
	}
}
