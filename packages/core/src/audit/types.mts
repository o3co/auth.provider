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
import type { AuditedError } from "./auditedError.mjs";

/**
 * Every audit-event type the bundled packages emit, pinned against the
 * emission sites in both directions by
 * `audit/__tests__/auditEventInventory.drift.test.mts`: an emission missing
 * here, or a name here with no emission left, fails CI.
 *
 * Names are dot-separated segments, most specific last, `snake_case` within a
 * segment: two for a plain subject-and-outcome (`authorize.granted`,
 * `rate_limit.unavailable`), more when the subject is namespaced
 * (`federation.token.family_revoked`, `token.issued.failure`). Consumers MAY
 * emit custom event types; namespace them so they cannot collide with future
 * entries here.
 */
export const BUILT_IN_AUDIT_EVENT_TYPES = [
	"authorize.granted",
	"authorize.rejected",
	"consent.denied",
	"consent.granted",
	"device.approved",
	"device.decision_outcome_unknown",
	"device.denied",
	"device.rate_limited",
	// Offline delegation: emitted by `retrieveFederationGrantToken` and carried
	// to the sink by the federation-grants routes, so the inventory guard scans
	// core's own `audit(...)` calls and `audits: [[...]]` tuples too.
	"federation.grant.authorization_failed",
	"federation.grant.authorized",
	"federation.grant.reauthorization_required",
	"federation.grant.reauthorized",
	"federation.grant.refresh_failed",
	"federation.grant.refresh_persist_failed",
	"federation.grant.refreshed",
	"federation.grant.request.denied",
	"federation.grant.requested",
	"federation.grant.revoke.denied",
	"federation.grant.revoked",
	"federation.grant.token.denied",
	"federation.grant.token.success",
	"federation.identity.link_refused",
	"federation.identity.linked",
	"federation.logout.idp_unreachable",
	"federation.logout.success",
	"federation.token.family_revoked",
	"federation.token.forbidden",
	"federation.token.reauthentication_required",
	"federation.token.refresh_failed",
	"federation.token.success",
	// An upstream token whose `token_type` this provider may not hand on.
	"federation.token.upstream_ineligible",
	"introspect.family_revoked",
	"introspect.session_invalid",
	"introspect.store_unavailable",
	"logout.cascade_failed",
	"logout.family_revoked",
	"logout.success",
	// Multi-factor authentication (the MFA ADR's D28), emitted by the MFA
	// package's routes; each carries `subject`, `ip` and `userAgent`, and
	// `kind` and `purpose` in its details. Listed before their emitters exist
	// (the inventory's drift test names each one's build step).
	"mfa.challenge.sent",
	"mfa.enrollment_state_inconsistent",
	"mfa.factor.enrolled",
	"mfa.factor.removed",
	"mfa.locked",
	"mfa.recovery_code.used",
	"mfa.recovery_codes.generated",
	"mfa.verified",
	"mfa.verify.failure",
	"rate_limit.unavailable",
	// A claim's subject that is not the record's, at any consumer of an
	// authenticated browser session (ADR 2026-09-28-session-admission).
	"session.admission.subject_mismatch",
	"token.issued",
	"token.issued.failure",
] as const;

export interface AuditEvent {
	readonly timestamp: Date;
	/**
	 * The event's type. The built-in vocabulary is
	 * {@link BUILT_IN_AUDIT_EVENT_TYPES}. Kept an open `string` because
	 * consumers emit custom, namespaced types of their own.
	 */
	readonly type: string;
	readonly subject?: string;
	readonly clientId?: string;
	/**
	 * The request's address — behind `trust proxy`, what the caller wrote in
	 * `X-Forwarded-For`. A sink is handed an IPv4 or IPv6 address, an IPv6
	 * zone stripped, or no `ip` at all (`recordAuditEvent`).
	 */
	readonly ip?: string;
	/** The request's `User-Agent`, the caller's own; a sink is handed it sanitised and capped. */
	readonly userAgent?: string;
	readonly details?: AuditEventDetails;
}

/**
 * An event's details: open, with one type per key across every event. A sink
 * that fixes a field's type the first time it sees it (Elasticsearch /
 * OpenSearch dynamic mapping, a BigQuery schema, a Datadog facet) drops the
 * events that disagree, so the two keys that could drift are typed here.
 */
export interface AuditEventDetails {
	/** A string where it appears: an OAuth error code, a refusal's reason. */
	readonly error?: string;
	/**
	 * The error an event reports, as `auditedError(err)` projects it — its
	 * name and code, one level of its cause, never its message.
	 */
	readonly cause?: AuditedError;
	readonly [key: string]: unknown;
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
 * attaches to it.
 *
 * `auditSink` is optional to wire but not to decide: `emitAuditEvent` is a
 * no-op on an empty slot, so a composition that never fills it discards every
 * security event with no symptom. Wire a sink, or write
 * `audit.sink.type = "none"` to own the decision in config. (The standalone
 * template always wires one; it has no "none" builder.)
 *
 * One shared constant, so the boot error's advice cannot depend on which
 * module tripped it; the declared-absence guard refuses policies that disagree.
 */
export const AUDIT_SINK_ABSENCE_POLICY = {
	configKey: ["audit", "sink", "type"],
	absentValue: "none",
	hint:
		"Without a sink every security event the routes emit (token issuance failures, " +
		"authorize decisions, rate-limit outages) is discarded.",
} as const;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge (optional slot)
//
// Declared here so oauthModule can list "auditSink" in its `optional` array
// and the DI graph types deps.auditSink as AuditSink | undefined. Optional to
// wire, not to decide: an unfilled slot must be declared with
// audit.sink.type = "none" or boot refuses (AUDIT_SINK_ABSENCE_POLICY).
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly auditSink?: AuditSink;
	}
}
