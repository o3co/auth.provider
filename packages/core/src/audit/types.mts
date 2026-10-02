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
	// Multi-factor authentication (the MFA ADR's D28), the MFA package's;
	// each carries `subject`, and the ceremonies' events `kind` and
	// `purpose` in their details. Those of its routes carry `ip` and
	// `userAgent`; the operator reset's `mfa.reset`, a library call with no
	// request behind it, carries neither. The MFA package is private until
	// the template wires it, so no released composition emits them. A
	// deployment notifies the account holder from seven of them, each
	// carrying, beside those, in its details:
	// `mfa.factor.enrolled` the factor's `binding` (`password`, `email_proof`,
	// `federated` or `mfa`) and `by: "user"`; `mfa.factor.removed`, a removal
	// from the account page, its `kind`, `factorId`, `binding` and `by: "user"`; `mfa.recovery_codes.generated` its `binding`,
	// `by: "user"`, `regenerated` (true when a set stood, or may have)
	// and, when an older set may still stand beside the new one,
	// `unreplaced: true` — with `kept: "password_binding"` when it was kept
	// on purpose; `mfa.locked.first`, the refusal that begins an episode (the
	// store's `first`), its `hold` and the refused attempt's factor `binding`;
	// `mfa.reset`, the operator reset, `by: "operator"`, the `kinds` and
	// `count` of the records it removed (none when they could not be read, or
	// the removal did not succeed),
	// `requireEmailProof`, `sessions` and `sessionsAgain` (every session
	// ended, before the removal and again after it), `complete` and,
	// when the operator named one, `requestedBy`;
	// `mfa.lock.recovered`, an authorized recovery applied to the subject's
	// lock state, its `operation`, the `generation` it moved to and what it
	// `cleared`; and
	// `mfa.email_address_mismatch`, the email factor refused because the
	// account's address no longer matches the one it was enrolled with,
	// nothing more — never an address. The event's `timestamp` is when.
	// `mfa.first_binding_conflict` — two logins of one subject bound a first
	// factor at once, and this one dropped its own: a password holder may be
	// racing the account's owner — carries the factor's `kind` and `removed`,
	// false when its factor could not be removed and may still stand.
	"mfa.challenge.sent",
	"mfa.email_address_mismatch",
	"mfa.enrollment_state_inconsistent",
	"mfa.factor.enrolled",
	"mfa.factor.removed",
	"mfa.first_binding_conflict",
	"mfa.lock.recovered",
	"mfa.locked",
	"mfa.locked.first",
	"mfa.recovery_code.used",
	"mfa.recovery_codes.generated",
	"mfa.reset",
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
	 *
	 * Once a module contributes `auditHooks`, `record` may run concurrently
	 * with the other sinks' for the same event; it must not mutate the event,
	 * which they share; and its failure is isolated from theirs.
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
 * security event with no symptom. Wire a sink, or list `auditSink` in core's
 * `core.declaredAbsent` to own the decision in config.
 *
 * One shared constant, so the boot error's advice cannot depend on which
 * module tripped it; the declared-absence guard refuses policies that disagree.
 */
export const AUDIT_SINK_ABSENCE_POLICY = {
	configKey: ["core", "declaredAbsent"],
	absentValue: "auditSink",
	hint:
		"Without a sink every security event the routes emit (token issuance failures, " +
		"authorize decisions, rate-limit outages) is discarded.",
} as const;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge (optional slot)
//
// Declared here so oauthModule can list "auditSink" in its `optional` array
// and the DI graph types deps.auditSink as AuditSink | undefined. Optional to
// wire, not to decide: an unfilled slot must be listed in
// core.declaredAbsent or boot refuses (AUDIT_SINK_ABSENCE_POLICY).
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly auditSink?: AuditSink;
	}
}
