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
 * Lodging an intent (#593, D6, D16, slice 6): the one place that orders the two
 * writes an acquisition makes, and the rules a backend's request is held to
 * before either is made.
 *
 * ## The order, and why it is this one
 *
 * 1. the intent store admits the intent — reserving its place against the
 *    bound;
 * 2. the grant store creates the `pending` grant naming it, or names it on the
 *    existing grant being renewed.
 *
 * Intent first, because the bound is the only admission control in front of
 * `createPending`. The other way round, every refused admission would already
 * have left a pending record behind, and the bound would cap nothing.
 *
 * What an interruption leaves:
 *
 * - after the first write, before the second: an orphan intent. It cannot pass
 *   `isCurrentIntent` — no grant names it — so it activates nothing, and it
 *   lapses with its deadline;
 * - a second write the store refused: the intent is closed, so nothing can
 *   reach it through a consent;
 * - a second write whose answer was lost: asked, not assumed.
 *   `isCurrentIntent` says whether it landed, and a write that landed is kept —
 *   undoing it would destroy a flow that may already be in front of the user.
 *   A `false` is never a reason to name the handle again: `nameIntent` is not
 *   safely retryable once a newer intent may have superseded this one.
 *
 * ## What it does not do
 *
 * It contacts no upstream, creates no consent, writes no credential, looks up
 * or provisions no local user, and establishes no session. `sub` is an
 * assertion here; the connect flow is what proves it (D7).
 */

import { randomBytes } from "node:crypto";
import { effectiveFederationGrantStatus } from "./effective-status.mjs";
import { resolveFederationGrantIntentScopes } from "./eligibility.mjs";
import {
	FEDERATION_GRANT_FLOW_BUDGET_MS,
	type FederationGrantIntent,
	type FederationGrantIntentStore,
} from "./intentStore.mjs";
import { resolveFederationGrantLifetimeMs } from "./lifetime.mjs";
import {
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
} from "./revision.mjs";
import type { FederationGrantStore } from "./store.mjs";
import type {
	FederationGrantConnection,
	FederationGrantExpiredReason,
	FederationGrantIneligibilityReason,
	FederationGrantRevokedBy,
} from "./types.mjs";

/** A connection as acquisition needs it: with the callback its flow returns to. */
export interface FederationGrantAcquisitionConnection extends FederationGrantConnection {
	/** `federationGrants.connections.<name>.callbackURL`, exactly as configured. */
	readonly callbackUri: string;
}

/** What lodging needs of the client that asked, as it was authenticated. */
export interface FederationGrantLodgingClient {
	readonly clientId: string;
	readonly allowedFederationGrantConnections?: readonly string[];
	readonly federationGrantRedirectUris?: readonly string[];
}

export interface FederationGrantLodgingDeps {
	readonly grantStore: FederationGrantStore;
	readonly intentStore: FederationGrantIntentStore;
	/** Every configured connection, by name. */
	readonly connections: ReadonlyMap<string, FederationGrantAcquisitionConnection>;
	/** Milliseconds. From `resolveFederationGrantAcquisitionLimits`. */
	readonly limits: { readonly defaultLifetimeMs: number; readonly maxLifetimeMs: number };
	/** Sampled at every write, not once per request: the race across a deadline depends on it. */
	readonly now?: () => Date;
	/** 256 bits, base64url. A seam for tests; the default is `randomBytes(32)`. */
	readonly randomId?: () => string;
	/** The subject's GRANTS boundary (D13) — never the sessions one. */
	readonly grantsRevokedBefore: (subject: string) => Promise<Date | null>;
	readonly revocationSkewMs: number;
	/** `federationGrants.maxExpiresIn`, in milliseconds, as retrieval reads it. */
	readonly maxExpiresInMs: number;
}

interface CommonRequest {
	readonly client: FederationGrantLodgingClient;
	readonly subject: string;
	readonly redirectUri: string;
	readonly clientState: string;
	/** Omitted means the connection's full set. */
	readonly scopes?: readonly string[];
	/** Omitted means the default. Clamped to the maximum, never refused for being large. */
	readonly requestedLifetimeMs?: number;
	readonly upstreamSubject?: string;
	readonly correlationId: string;
}

export interface FederationGrantLodgingRequest extends CommonRequest {
	readonly connection: string;
}

export interface FederationGrantReauthorizationRequest extends CommonRequest {
	readonly grantId: string;
}

/** Why a request was refused before anything was written, or why a write failed. */
export type FederationGrantLodgingRefusal =
	| "connection_not_permitted"
	| "connection_not_configured"
	| "redirect_uri_not_registered"
	| "redirect_uri_reserved_parameter"
	| "scope_exceeded"
	| "openid_required"
	| "offline_access_required"
	| "scope_subsets_not_allowed"
	| "expires_in_out_of_range"
	| "intent_limit"
	| "storage";

export interface FederationGrantLodged {
	readonly ok: true;
	readonly grantId: string;
	/** What `connect_uri` carries. Single-use, 256 bits. */
	readonly handle: string;
	/** The flow's one deadline. */
	readonly intentExpiresAt: Date;
	/** The grant lifetime that applied, after the clamp. */
	readonly lifetimeMs: number;
}

export type FederationGrantLodgingResult =
	| FederationGrantLodged
	| { readonly ok: false; readonly reason: FederationGrantLodgingRefusal };

export type FederationGrantReauthorizationResult =
	| (FederationGrantLodged & {
			/** The grant's effective status, unchanged: a renewal does not make it pending. */
			readonly status: "active" | "reauthorization_required";
	  })
	| { readonly ok: false; readonly reason: FederationGrantLodgingRefusal }
	| { readonly ok: false; readonly reason: "grant_not_found" | "authorization_pending" }
	| { readonly ok: false; readonly reason: "connection_identity_changed" }
	| {
			readonly ok: false;
			readonly reason: "grant_revoked";
			readonly revokedBy: FederationGrantRevokedBy;
			/** Whether THIS call wrote the revocation — what decides whether it is audited. */
			readonly revokedNow: boolean;
	  }
	| {
			readonly ok: false;
			readonly reason: "grant_expired";
			readonly expiredBy: FederationGrantExpiredReason;
	  }
	| {
			readonly ok: false;
			readonly reason: "upstream_token_ineligible";
			readonly ineligibleBy: FederationGrantIneligibilityReason;
	  }
	| { readonly ok: false; readonly reason: "key_unavailable" };

/**
 * The result parameters the end of a flow appends to a client's redirect URI.
 * One the registered URI already carries would reach the client twice — once
 * as the client wrote it, once as this provider did — and which a client reads
 * is its framework's choice, not a contract.
 */
const RESERVED_RESULT_PARAMETERS = ["grant_id", "state", "error"] as const;

/**
 * The reserved result parameter a redirect URI already carries, if any.
 *
 * Exported so that where the URI is REGISTERED can refuse it too — at boot, for
 * a deployment whose clients are configured — and lodging keeps refusing it as
 * the belt for a repository that validates nothing.
 */
export function federationGrantRedirectUriReservedParameter(uri: string): string | undefined {
	let parsed: URL;
	try {
		parsed = new URL(uri);
	} catch {
		return undefined;
	}
	return RESERVED_RESULT_PARAMETERS.find((name) => parsed.searchParams.has(name));
}

const defaultRandomId = (): string => randomBytes(32).toString("base64url");

type RequestCheck =
	| {
			readonly ok: true;
			readonly scopes: readonly string[];
			readonly lifetimeMs: number;
	  }
	| { readonly ok: false; readonly reason: FederationGrantLodgingRefusal };

/**
 * What a first intent and a renewal are held to alike: where the browser goes
 * back to, what may be asked, and for how long. The connection has already been
 * chosen — by name for a first intent, from the grant for a renewal.
 */
function checkRequest(
	deps: FederationGrantLodgingDeps,
	request: CommonRequest,
	connection: FederationGrantAcquisitionConnection,
): RequestCheck {
	const registered = request.client.federationGrantRedirectUris ?? [];
	// Exact membership, and nothing else: no prefix, no normalization, no
	// fallback to the client's ordinary redirect URIs.
	if (!registered.includes(request.redirectUri)) {
		return { ok: false, reason: "redirect_uri_not_registered" };
	}
	if (federationGrantRedirectUriReservedParameter(request.redirectUri) !== undefined) {
		return { ok: false, reason: "redirect_uri_reserved_parameter" };
	}

	const scopes = resolveFederationGrantIntentScopes(request.scopes, connection);
	if (!scopes.ok) {
		switch (scopes.reason) {
			case "outside_connection":
				return { ok: false, reason: "scope_exceeded" };
			case "subsets_not_allowed":
				return { ok: false, reason: "scope_subsets_not_allowed" };
			case "required_scope_missing": {
				const asked = new Set(request.scopes ?? []);
				return {
					ok: false,
					reason: asked.has("openid") ? "offline_access_required" : "openid_required",
				};
			}
		}
	}

	const requested = request.requestedLifetimeMs;
	if (requested !== undefined && !(Number.isSafeInteger(requested) && requested > 0)) {
		return { ok: false, reason: "expires_in_out_of_range" };
	}
	const lifetimeMs = resolveFederationGrantLifetimeMs({
		...(requested !== undefined ? { requestedMs: requested } : {}),
		defaultMs: deps.limits.defaultLifetimeMs,
		maxMs: deps.limits.maxLifetimeMs,
	});
	return { ok: true, scopes: scopes.scopes, lifetimeMs };
}

const permits = (client: FederationGrantLodgingClient, connection: string): boolean =>
	(client.allowedFederationGrantConnections ?? []).includes(connection);

function intentRecord(input: {
	readonly handle: string;
	readonly kind: FederationGrantIntent["kind"];
	readonly grantId: string;
	readonly request: CommonRequest;
	readonly connection: FederationGrantAcquisitionConnection;
	readonly scopes: readonly string[];
	readonly lifetimeMs: number;
	readonly now: Date;
}): FederationGrantIntent {
	const { request, connection } = input;
	return {
		handle: input.handle,
		kind: input.kind,
		grantId: input.grantId,
		clientId: request.client.clientId,
		subject: request.subject,
		connection: connection.name,
		federation: connection.federation,
		identityRevision: federationGrantIdentityRevision(connection),
		authorizationRevision: federationGrantAuthorizationRevision(connection),
		callbackUri: connection.callbackUri,
		scopes: [...input.scopes],
		...(connection.resource !== undefined ? { resource: connection.resource } : {}),
		authorizationParams: { ...(connection.authorizationParams ?? {}) },
		redirectUri: request.redirectUri,
		clientState: request.clientState,
		...(request.upstreamSubject !== undefined ? { upstreamSubject: request.upstreamSubject } : {}),
		lifetimeMs: input.lifetimeMs,
		createdAt: input.now,
		expiresAt: new Date(input.now.getTime() + FEDERATION_GRANT_FLOW_BUDGET_MS),
		correlationId: request.correlationId,
	};
}

type Admitted =
	| { readonly ok: true }
	| { readonly ok: false; readonly reason: "intent_limit" | "storage" };

async function admit(
	store: FederationGrantIntentStore,
	record: FederationGrantIntent,
	now: Date,
): Promise<Admitted> {
	let written: Awaited<ReturnType<FederationGrantIntentStore["putIntent"]>>;
	try {
		written = await store.putIntent(record, now);
	} catch {
		return { ok: false, reason: "storage" };
	}
	if (written.outcome !== "refused") return { ok: true };
	// A fresh 256-bit handle that collides, or a deadline ten minutes out that
	// has already passed, is a fault on this side and not the client's.
	return { ok: false, reason: written.reason === "limit" ? "intent_limit" : "storage" };
}

/** Ends an intent nothing will ever reach. Best effort: its deadline ends it anyway. */
async function close(store: FederationGrantIntentStore, handle: string, now: Date): Promise<void> {
	try {
		await store.finishIntent(handle, now);
	} catch {
		// The intent cannot activate anything without a grant naming it, and it
		// lapses with the flow budget. Failing the request over its cleanup would
		// report an outage for something already harmless.
	}
}

/**
 * Lodges a first-time intent: validates what the client asked for, admits the
 * intent, and creates the `pending` grant that names it (D6, D16).
 */
export async function lodgeFederationGrantIntent(
	deps: FederationGrantLodgingDeps,
	request: FederationGrantLodgingRequest,
): Promise<FederationGrantLodgingResult> {
	const now = deps.now ?? (() => new Date());
	const randomId = deps.randomId ?? defaultRandomId;

	// Permission before existence: which connections a deployment has is not
	// something a client may probe for.
	if (!permits(request.client, request.connection)) {
		return { ok: false, reason: "connection_not_permitted" };
	}
	const connection = deps.connections.get(request.connection);
	if (connection === undefined) return { ok: false, reason: "connection_not_configured" };

	const checked = checkRequest(deps, request, connection);
	if (!checked.ok) return checked;

	const grantId = randomId();
	const handle = randomId();
	const lodgedAt = now();
	const record = intentRecord({
		handle,
		kind: "initial",
		grantId,
		request,
		connection,
		scopes: checked.scopes,
		lifetimeMs: checked.lifetimeMs,
		now: lodgedAt,
	});

	const admitted = await admit(deps.intentStore, record, lodgedAt);
	if (!admitted.ok) return admitted;

	const created = await secondWrite(
		() =>
			deps.grantStore.createPending({
				id: grantId,
				subject: request.subject,
				clientId: request.client.clientId,
				connection: connection.name,
				intent: { handle, expiresAt: record.expiresAt },
				now: now(),
			}),
		() => deps.grantStore.isCurrentIntent(grantId, handle, now()),
	);
	if (!created) {
		await close(deps.intentStore, handle, now());
		return { ok: false, reason: "storage" };
	}
	return {
		ok: true,
		grantId,
		handle,
		intentExpiresAt: record.expiresAt,
		lifetimeMs: checked.lifetimeMs,
	};
}

/**
 * The grant-store write, with its answer asked for rather than assumed when it
 * was lost. `true` only when the write is known to have landed.
 */
async function secondWrite(
	write: () => Promise<{ readonly ok: boolean }>,
	landed: () => Promise<boolean>,
): Promise<boolean> {
	try {
		return (await write()).ok;
	} catch {
		try {
			return await landed();
		} catch {
			return false;
		}
	}
}

/**
 * Lodges a renewal of an existing grant (D6): ownership, then the revocation
 * backstop before anything else is asked of it (D13), then what a renewal can
 * and cannot mend, then the client's current permission and its request — and
 * only then the two writes.
 */
export async function lodgeFederationGrantReauthorization(
	deps: FederationGrantLodgingDeps,
	request: FederationGrantReauthorizationRequest,
): Promise<FederationGrantReauthorizationResult> {
	const now = deps.now ?? (() => new Date());
	const randomId = deps.randomId ?? defaultRandomId;

	let inspection: Awaited<ReturnType<FederationGrantStore["inspect"]>>;
	try {
		inspection = await deps.grantStore.inspect(request.grantId, now());
	} catch {
		return { ok: false, reason: "storage" };
	}
	// One answer for an unknown grant, another client's and another subject's:
	// a grant ID proves nothing, and whose grant it is must not be learnable
	// from how the refusal reads.
	if (
		inspection === null ||
		inspection.grant.clientId !== request.client.clientId ||
		inspection.grant.subject !== request.subject
	) {
		return { ok: false, reason: "grant_not_found" };
	}

	let boundary: Date | null;
	try {
		boundary = await deps.grantsRevokedBefore(request.subject);
		if (boundary !== null && !(boundary instanceof Date && !Number.isNaN(boundary.getTime()))) {
			throw new TypeError("the grants boundary is neither a date nor null");
		}
	} catch {
		// Fails closed: a boundary that cannot be read is not "nothing revoked".
		return { ok: false, reason: "storage" };
	}

	return await judgeAndLodge(deps, request, inspection, boundary, now, randomId);
}

type Inspection = NonNullable<Awaited<ReturnType<FederationGrantStore["inspect"]>>>;

/** The grant's effective status, as a reauthorization judges it. */
function statusOf(
	deps: FederationGrantLodgingDeps,
	inspection: Inspection,
	boundary: Date | null,
	at: Date,
) {
	return effectiveFederationGrantStatus(inspection.grant, {
		now: at,
		connection: deps.connections.get(inspection.grant.connection),
		maxExpiresInMs: deps.maxExpiresInMs,
		grantsBoundary: boundary,
		revocationSkewMs: deps.revocationSkewMs,
		credentials: inspection.credentials === "ok" ? "ok" : "unreadable",
	});
}

/**
 * What a reauthorization cannot mend, as the answer it gets — or `null` for the
 * two statuses D6 accepts, `active` and `reauthorization_required`. A grant
 * reading as `upstream_token_ineligible` is refused although a renewal would
 * clear the marker: that it would is not a reason to widen D6's accepted set.
 */
function lifecycleRefusal(
	status: ReturnType<typeof effectiveFederationGrantStatus>,
): FederationGrantReauthorizationResult | null {
	switch (status.status) {
		case "revoked":
			return { ok: false, reason: "grant_revoked", revokedBy: status.reason, revokedNow: false };
		case "pending":
			return { ok: false, reason: "authorization_pending" };
		case "expired":
			return { ok: false, reason: "grant_expired", expiredBy: status.reason };
		case "connection_not_configured":
			return { ok: false, reason: "connection_not_configured" };
		case "connection_identity_changed":
			return { ok: false, reason: "connection_identity_changed" };
		case "upstream_token_ineligible":
			return { ok: false, reason: "upstream_token_ineligible", ineligibleBy: status.reason };
		case "active":
		case "reauthorization_required":
			return null;
	}
}

async function judgeAndLodge(
	deps: FederationGrantLodgingDeps,
	request: FederationGrantReauthorizationRequest,
	inspection: Inspection,
	boundary: Date | null,
	now: () => Date,
	randomId: () => string,
): Promise<FederationGrantReauthorizationResult> {
	const { grant } = inspection;
	const status = statusOf(deps, inspection, boundary, now());

	if (status.status === "revoked" && status.reason === "backstop" && grant.status !== "revoked") {
		// Written down, not only reported: a revocation that lived only in the
		// comparison would vanish the day the boundary is lost.
		let written: Awaited<ReturnType<FederationGrantStore["revoke"]>>;
		try {
			written = await deps.grantStore.revoke(grant.id, "backstop", now());
		} catch {
			return { ok: false, reason: "storage" };
		}
		return { ok: false, reason: "grant_revoked", revokedBy: "backstop", revokedNow: written.ok };
	}
	const refused = lifecycleRefusal(status);
	if (refused !== null) return refused;
	if (
		status.status === "reauthorization_required" &&
		status.reason === "credential_unreadable" &&
		inspection.credentials === "key_unavailable"
	) {
		// A key missing from the ring is an outage, not a reason to send the user
		// to consent again.
		return { ok: false, reason: "key_unavailable" };
	}
	// Defined here: a connection that is not configured was refused above.
	const connection = deps.connections.get(grant.connection) as FederationGrantAcquisitionConnection;

	if (!permits(request.client, connection.name)) {
		return { ok: false, reason: "connection_not_permitted" };
	}
	const checked = checkRequest(deps, request, connection);
	if (!checked.ok) return checked;

	const handle = randomId();
	const lodgedAt = now();
	const record = intentRecord({
		handle,
		kind: "reauthorization",
		grantId: grant.id,
		request,
		connection,
		scopes: checked.scopes,
		lifetimeMs: checked.lifetimeMs,
		now: lodgedAt,
	});
	const admitted = await admit(deps.intentStore, record, lodgedAt);
	if (!admitted.ok) return admitted;

	const named = await secondWrite(
		() =>
			deps.grantStore.nameIntent({
				grantId: grant.id,
				intent: { handle, expiresAt: record.expiresAt },
				now: now(),
			}),
		() => deps.grantStore.isCurrentIntent(grant.id, handle, now()),
	);
	if (named) {
		return {
			ok: true,
			grantId: grant.id,
			handle,
			intentExpiresAt: record.expiresAt,
			lifetimeMs: checked.lifetimeMs,
			status: status.status === "active" ? "active" : "reauthorization_required",
		};
	}

	await close(deps.intentStore, handle, now());
	// The pointer write lost: the grant changed under this request. What it is
	// NOW is the answer — never a retry on the strength of the stale reading,
	// which could renew a grant revoked in between.
	let fresh: Awaited<ReturnType<FederationGrantStore["inspect"]>>;
	try {
		fresh = await deps.grantStore.inspect(grant.id, now());
	} catch {
		return { ok: false, reason: "storage" };
	}
	if (fresh === null) return { ok: false, reason: "grant_not_found" };
	// Still renewable: the write lost to something that left it so, and the
	// honest answer is that this attempt did not take.
	return (
		lifecycleRefusal(statusOf(deps, fresh, boundary, now())) ?? { ok: false, reason: "storage" }
	);
}
