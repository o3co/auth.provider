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

/**
 * Every audit-event type the bundled packages emit (#369).
 *
 * This used to be an informative doc comment, and it had drifted badly: it
 * named events nothing emits (`"logout"`, `"scope.denied"`,
 * `"login.success"`, the `"mfa.challenge.*"` family) and omitted most of
 * what IS emitted — so a sink implementor or dashboard author filtering on
 * the documented names matched nothing. The list is now a constant, pinned
 * against the actual emission sites in both directions by
 * `audit/__tests__/auditEventInventory.drift.test.mts`: adding an emission
 * without listing it here fails CI, and so does keeping a name here after
 * its last emission site is removed.
 *
 * The naming convention is dot-separated segments, most specific last and
 * `snake_case` within one segment — two segments for a plain
 * subject-and-outcome (`authorize.granted`, `rate_limit.unavailable`),
 * more when the subject itself is namespaced
 * (`federation.token.family_revoked`, `token.issued.failure`). Consumers
 * MAY emit custom event types; namespace them so they cannot collide with
 * future entries here.
 */
export const BUILT_IN_AUDIT_EVENT_TYPES = [
	"authorize.granted",
	"authorize.rejected",
	"device.approved",
	"device.denied",
	"device.rate_limited",
	"federation.logout.idp_unreachable",
	"federation.logout.success",
	"federation.token.family_revoked",
	"federation.token.forbidden",
	"federation.token.reauthentication_required",
	"federation.token.refresh_failed",
	"federation.token.success",
	"introspect.family_revoked",
	"introspect.session_invalid",
	"introspect.store_unavailable",
	"logout.cascade_failed",
	"logout.family_revoked",
	"logout.success",
	"rate_limit.unavailable",
	"token.issued",
	"token.issued.failure",
] as const;

export interface AuditEvent {
	readonly timestamp: Date;
	/**
	 * The event's type. The built-in vocabulary is
	 * {@link BUILT_IN_AUDIT_EVENT_TYPES} — a constant rather than prose, so
	 * the inventory cannot drift from the emission sites again. Kept an open
	 * `string` because consumers emit custom, namespaced types of their own.
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
