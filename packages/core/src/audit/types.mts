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

/**
 * The declared-absence policy every bundled module that reads `auditSink`
 * attaches to it (#363, the sink half of #287).
 *
 * `auditSink` stays optional to wire — which sink is a configuration
 * question — but not optional to decide: `emitAuditEvent` is a no-op on an
 * empty slot, so a composition that simply never fills it discards every
 * security event with no symptom, which is how the standalone template
 * shipped eventless until #287. The template answers by always wiring a sink
 * (`audit.sink.type` has no "none" builder there); every other composition
 * answers here — wire a sink, or write `audit.sink.type = "none"` and own
 * the decision in config.
 *
 * One shared constant rather than three per-module copies, so the boot
 * error's advice cannot depend on which module tripped it — the
 * declared-absence guard refuses policies that disagree.
 */
export const AUDIT_SINK_ABSENCE_POLICY = {
	configKey: ["audit", "sink", "type"],
	absentValue: "none",
	hint:
		"Without a sink every security event the routes emit (token issuance failures, " +
		"authorize decisions, rate-limit outages) is discarded.",
} as const;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge (A2-α §6.1 — optional slot)
//
// Declared here so oauthModule can list "auditSink" in its `optional` array
// and the DI graph types deps.auditSink as AuditSink | undefined.
// The slot is optional to WIRE: when absent, oauth routes emit no audit
// events (the emitAuditEvent helper is a no-op when sink is undefined). It is
// no longer optional to DECIDE: the bundled modules attach
// AUDIT_SINK_ABSENCE_POLICY, so an unfilled slot must be declared with
// audit.sink.type = "none" or boot refuses (#363).
// Phase 9 Task 4 augmentation.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly auditSink?: AuditSink;
	}
}
