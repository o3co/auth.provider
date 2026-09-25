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
 * A `storage` refusal carries what failed (`failure`): which store, what it
 * was asked, what it threw or refused — for the route answering the 503 to
 * log once. Any answer, a success included, carries every store error it
 * does not itself stand for (`absorbed`): a second write that threw and
 * landed all the same, the question after one that could not be asked, a
 * pointer write whose re-read decided the answer, an intent that could not
 * be closed — for the route to log as what they are. A
 * `connection_not_configured` refusal carries the connection it is about
 * (`connection`). None of the three is enumerable (`carry.mts`).
 *
 * ## What it does not do
 *
 * It contacts no upstream, creates no consent, writes no credential, looks up
 * or provisions no local user, and establishes no session. `sub` is an
 * assertion here; the connect flow is what proves it (D7).
 */

import { randomBytes } from "node:crypto";
import { checkRedirectUri } from "../net/redirect-uri.mjs";
import { federationGrantAllowlist } from "./allowlist.mjs";
import { carrying, carryingFailure } from "./carry.mjs";
import { effectiveFederationGrantStatus } from "./effective-status.mjs";
import { resolveFederationGrantIntentScopes } from "./eligibility.mjs";
import {
	FEDERATION_GRANT_FLOW_BUDGET_MS,
	type FederationGrantIntent,
	type FederationGrantIntentRefusal,
	type FederationGrantIntentStore,
} from "./intentStore.mjs";
import { resolveFederationGrantLifetimeMs } from "./lifetime.mjs";
import {
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
} from "./revision.mjs";
import type { FederationGrantStore } from "./store.mjs";
import type {
	FederationGrant,
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
	/**
	 * The connection the caller believes the grant is on — an assertion, as on
	 * the token route, and never a way to move the grant to another one.
	 */
	readonly connection?: string;
}

/** Why a request was refused before anything was written, or why a write failed. */
export type FederationGrantLodgingRefusal =
	| "connection_not_permitted"
	| "connection_not_configured"
	| "redirect_uri_not_registered"
	| "redirect_uri_invalid"
	| "redirect_uri_reserved_parameter"
	| "scope_exceeded"
	| "openid_required"
	| "offline_access_required"
	| "scope_subsets_not_allowed"
	| "expires_in_out_of_range"
	| "intent_limit"
	| "storage";

export interface FederationGrantLodged extends FederationGrantLodgingAbsorbedCarrier {
	readonly ok: true;
	readonly grantId: string;
	/** What `connect_uri` carries. Single-use, 256 bits. */
	readonly handle: string;
	/** The flow's one deadline. */
	readonly intentExpiresAt: Date;
	/** The grant lifetime that applied, after the clamp. */
	readonly lifetimeMs: number;
	/** What was lodged, for the audit of it: the connection, the resolved scopes, the resource. */
	readonly connection: string;
	readonly scopes: readonly string[];
	readonly resource?: string;
}

/**
 * What failed where a lodging answered `storage`, carried on the refusal as
 * its `failure` — a property nothing enumerates (`carry.mts`), so that a
 * spread, a serialisation or a response built from the refusal never carries
 * it. For a logger; never for a response: a store's error can carry what it
 * was sent.
 */
export interface FederationGrantLodgingFailure {
	/** What could not answer: the intent store, the grant store, or the subject's grants boundary. */
	readonly store: "federation_grant_intent" | "federation_grant" | "revocation_boundary";
	/** What it was asked. */
	readonly step: "put_intent" | "create_pending" | "name_intent" | "inspect" | "read" | "revoke";
	/** What it threw. Absent where it answered with a refusal instead. */
	readonly error?: unknown;
	/**
	 * A refusal that is a fault on this side, where nothing was thrown: the
	 * intent store's `collision`, `expired` or `closed`, or `refused` for a
	 * grant-store write whose guard refused it.
	 */
	readonly refusal?: Exclude<FederationGrantIntentRefusal, "limit"> | "refused";
}

/**
 * A store error a lodging's answer does not stand for. None changes the
 * answer; each is for a logger, never for a response:
 *
 * - a second write (`create_pending`, `name_intent`) that threw and landed all
 *   the same, or whose re-read decided the answer instead;
 * - the question after a second write that threw (`is_current_intent`), when
 *   it could not be asked;
 * - the intent the lodging could not close after a failed write
 *   (`finish_intent`) — best effort: it can activate nothing, since no grant
 *   names it, and its deadline ends it.
 */
export interface FederationGrantLodgingStepFailure {
	readonly store: "federation_grant" | "federation_grant_intent";
	readonly step: "create_pending" | "name_intent" | "is_current_intent" | "finish_intent";
	readonly error: unknown;
}

/** What any lodging answer, a success included, may carry beside it. */
export interface FederationGrantLodgingAbsorbedCarrier {
	/**
	 * The store errors the answer does not stand for, in the order they
	 * happened. Not enumerable (`carry.mts`): nothing that serialises the
	 * answer carries them.
	 */
	readonly absorbed?: readonly FederationGrantLodgingStepFailure[];
}

/** A refusal; on `storage`, carrying what failed. */
export interface FederationGrantLodgingRefused extends FederationGrantLodgingAbsorbedCarrier {
	readonly ok: false;
	readonly reason: FederationGrantLodgingRefusal;
	/** On `storage`: what failed — a `FederationGrantLodgingFailure`, not enumerable (`carry.mts`). */
	readonly failure?: FederationGrantLodgingFailure;
	/**
	 * On `connection_not_configured`: the connection it is about — the one the
	 * request named, or the renewed grant's, which a renewal need not name.
	 * Not enumerable (`carry.mts`).
	 */
	readonly connection?: string;
}

export type FederationGrantLodgingResult = FederationGrantLodged | FederationGrantLodgingRefused;

export type FederationGrantReauthorizationResult =
	| (FederationGrantLodged & {
			/**
			 * The grant's effective status, unchanged: a renewal does not make it
			 * pending, and does not end a starvation — `upstream_token_ineligible`
			 * is what a grant admitted for `scope_exceeded` still reads (#616).
			 */
			readonly status: FederationGrantRenewableStatus;
	  })
	| FederationGrantLodgingRefused
	| ((
			| {
					readonly ok: false;
					readonly reason: "grant_not_found" | "authorization_pending" | "connection_mismatch";
			  }
			| { readonly ok: false; readonly reason: "connection_identity_changed" }
			| {
					readonly ok: false;
					readonly reason: "grant_revoked";
					readonly revokedBy: FederationGrantRevokedBy;
					/** Whether THIS call wrote the revocation — what decides whether it is audited. */
					readonly revokedNow: boolean;
					/** The record the write returned, when `revokedNow`: what the audit of it describes (D18). */
					readonly revoked?: FederationGrant;
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
			| { readonly ok: false; readonly reason: "key_unavailable" }
	  ) &
			FederationGrantLodgingAbsorbedCarrier);

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
	| FederationGrantLodgingRefused;

/** `storage`, carrying what failed where nothing enumerates it (`carry.mts`). */
const storage = (failure: FederationGrantLodgingFailure): FederationGrantLodgingRefused =>
	carryingFailure({ ok: false, reason: "storage" }, failure);

/** Every answer a renewal refuses with. */
type ReauthorizationRefusal = Extract<FederationGrantReauthorizationResult, { readonly ok: false }>;

/**
 * `answer`, carrying the store errors it does not stand for, when there are
 * any — whatever the answer is (`carry.mts`).
 */
const absorbing = <T extends FederationGrantLodgingResult | FederationGrantReauthorizationResult>(
	answer: T,
	absorbed: readonly FederationGrantLodgingStepFailure[],
): T => carrying(answer, "absorbed", absorbed.length === 0 ? undefined : absorbed);

/** The intent that could not be closed, as the step failure it is; nothing when it closed. */
const leftOpen = (closed: Closed): FederationGrantLodgingStepFailure[] =>
	closed === undefined
		? []
		: [{ store: "federation_grant_intent", step: "finish_intent", error: closed.error }];

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
	// Read as a list or as nothing (`federationGrantAllowlist`): a repository
	// answering a string would otherwise match by substring.
	const registered = federationGrantAllowlist(request.client.federationGrantRedirectUris);
	// Exact membership, and nothing else: no prefix, no normalization, no
	// fallback to the client's ordinary redirect URIs.
	if (!registered.includes(request.redirectUri)) {
		return { ok: false, reason: "redirect_uri_not_registered" };
	}
	// Registered, and still held to what registration would have refused: a
	// repository that validates nothing could hand back a URI that does not
	// parse, and the flow would fail only at its end — after activating the
	// grant — when the browser has to be sent there (the adversarial review).
	if (checkRedirectUri(request.redirectUri) !== null) {
		return { ok: false, reason: "redirect_uri_invalid" };
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
	federationGrantAllowlist(client.allowedFederationGrantConnections).includes(connection);

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
		resource: connection.resource,
		authorizationParams: { ...(connection.authorizationParams ?? {}) },
		redirectUri: request.redirectUri,
		clientState: request.clientState,
		upstreamSubject: request.upstreamSubject,
		lifetimeMs: input.lifetimeMs,
		createdAt: input.now,
		expiresAt: new Date(input.now.getTime() + FEDERATION_GRANT_FLOW_BUDGET_MS),
		correlationId: request.correlationId,
	};
}

type Admitted = { readonly ok: true } | FederationGrantLodgingRefused;

async function admit(
	store: FederationGrantIntentStore,
	record: FederationGrantIntent,
	now: Date,
): Promise<Admitted> {
	let written: Awaited<ReturnType<FederationGrantIntentStore["putIntent"]>>;
	try {
		written = await store.putIntent(record, now);
	} catch (error) {
		return storage({ store: "federation_grant_intent", step: "put_intent", error });
	}
	if (written.outcome !== "refused") return { ok: true };
	if (written.reason === "limit") return { ok: false, reason: "intent_limit" };
	// A fresh 256-bit handle that collides, or a deadline ten minutes out that
	// has already passed, is a fault on this side and not the client's.
	return storage({ store: "federation_grant_intent", step: "put_intent", refusal: written.reason });
}

/** What closing an intent came to: nothing, or the error it failed with. */
type Closed = { readonly error: unknown } | undefined;

/**
 * Ends an intent nothing will ever reach. Best effort: its deadline ends it
 * anyway, so a failure fails nothing — it is handed back to ride on whichever
 * answer follows (`absorbed`), where the route logs it as what it is.
 */
async function close(
	store: FederationGrantIntentStore,
	handle: string,
	now: Date,
): Promise<Closed> {
	try {
		await store.finishIntent(handle, now);
		return undefined;
	} catch (error) {
		// The intent cannot activate anything without a grant naming it, and it
		// lapses with the flow budget. Failing the request over its cleanup would
		// report an outage for something already harmless.
		return { error };
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
	if (connection === undefined) {
		return carrying<FederationGrantLodgingRefused>(
			{ ok: false, reason: "connection_not_configured" },
			"connection",
			request.connection,
		);
	}

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
		"create_pending",
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
	if (!created.landed) {
		const closed = await close(deps.intentStore, handle, now());
		return absorbing(
			storage({ store: "federation_grant", step: "create_pending", ...created.why }),
			[...created.absorbed, ...leftOpen(closed)],
		);
	}
	return absorbing<FederationGrantLodgingResult>(
		{
			ok: true,
			grantId,
			handle,
			intentExpiresAt: record.expiresAt,
			lifetimeMs: checked.lifetimeMs,
			connection: connection.name,
			scopes: record.scopes,
			...(record.resource === undefined ? {} : { resource: record.resource }),
		},
		created.absorbed,
	);
}

/**
 * A second write: landed, or why not — the error it threw, or the store's
 * refusal — and the store errors met on the way that the outcome does not
 * stand for.
 */
type SecondWrite =
	| { readonly landed: true; readonly absorbed: readonly FederationGrantLodgingStepFailure[] }
	| {
			readonly landed: false;
			readonly why: { readonly error: unknown } | { readonly refusal: "refused" };
			readonly absorbed: readonly FederationGrantLodgingStepFailure[];
	  };

/**
 * The grant-store write, with its answer asked for rather than assumed when it
 * was lost. `landed` only when the write is known to have landed. A write that
 * threw and did not land — or could not be asked about — carries its own
 * error: that is the failure. What is kept beside it: the write's error when
 * it landed all the same, and the question's error when it could not be
 * asked.
 */
async function secondWrite(
	step: "create_pending" | "name_intent",
	write: () => Promise<{ readonly ok: boolean }>,
	landed: () => Promise<boolean>,
): Promise<SecondWrite> {
	let thrown: unknown;
	try {
		return (await write()).ok
			? { landed: true, absorbed: [] }
			: { landed: false, why: { refusal: "refused" }, absorbed: [] };
	} catch (error) {
		thrown = error;
	}
	try {
		if (await landed()) {
			return { landed: true, absorbed: [{ store: "federation_grant", step, error: thrown }] };
		}
	} catch (error) {
		// Not known to have landed: the write's own error is what failed, and
		// the question that could not be asked is kept beside it.
		return {
			landed: false,
			why: { error: thrown },
			absorbed: [{ store: "federation_grant", step: "is_current_intent", error }],
		};
	}
	return { landed: false, why: { error: thrown }, absorbed: [] };
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
	} catch (error) {
		return storage({ store: "federation_grant", step: "inspect", error });
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
	} catch (error) {
		// Fails closed: a boundary that cannot be read is not "nothing revoked".
		return storage({ store: "revocation_boundary", step: "read", error });
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

/** The statuses a renewal is admitted from, which its 201 reports unchanged (D6, #616). */
export type FederationGrantRenewableStatus =
	| "active"
	| "reauthorization_required"
	| "upstream_token_ineligible";

/** What the lifecycle says of a renewal: the status it is admitted from, or the answer it gets instead. */
type Admission =
	| { readonly admitted: FederationGrantRenewableStatus }
	| { readonly refused: ReauthorizationRefusal };

/**
 * What a reauthorization cannot mend, as the answer it gets — or the status it
 * is admitted from, for what D6 admits: `active`, `reauthorization_required`,
 * and (#616) a grant starved of scope. An IdP that accumulates consent answers
 * a narrower grant's refresh with a wider grant's scopes, and a wider consent
 * is exactly the remedy; the other ineligibilities — a lifetime, a type, a
 * shape no consent changes — are refused as ever, and judged as they read
 * NOW, not as a marker was left: a maximum no token can satisfy outranks an
 * old scope marker. The admitted status is what the 201 reports, unchanged.
 */
function admission(
	status: ReturnType<typeof effectiveFederationGrantStatus>,
	connection: string,
): Admission {
	switch (status.status) {
		case "revoked":
			return {
				refused: {
					ok: false,
					reason: "grant_revoked",
					revokedBy: status.reason,
					revokedNow: false,
				},
			};
		case "pending":
			return { refused: { ok: false, reason: "authorization_pending" } };
		case "expired":
			return { refused: { ok: false, reason: "grant_expired", expiredBy: status.reason } };
		case "connection_not_configured":
			// The grant's: a renewal need not name the connection it renews.
			return {
				refused: carrying<ReauthorizationRefusal>(
					{ ok: false, reason: "connection_not_configured" },
					"connection",
					connection,
				),
			};
		case "connection_identity_changed":
			return { refused: { ok: false, reason: "connection_identity_changed" } };
		case "upstream_token_ineligible":
			return status.reason === "scope_exceeded"
				? { admitted: "upstream_token_ineligible" }
				: {
						refused: {
							ok: false,
							reason: "upstream_token_ineligible",
							ineligibleBy: status.reason,
						},
					};
		case "active":
		case "reauthorization_required":
			return { admitted: status.status };
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
		} catch (error) {
			return storage({ store: "federation_grant", step: "revoke", error });
		}
		return written.ok
			? {
					ok: false,
					reason: "grant_revoked",
					revokedBy: "backstop",
					revokedNow: true,
					revoked: written.grant,
				}
			: { ok: false, reason: "grant_revoked", revokedBy: "backstop", revokedNow: false };
	}
	const judged = admission(status, grant.connection);
	if ("refused" in judged) return judged.refused;
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

	if (request.connection !== undefined && request.connection !== grant.connection) {
		return { ok: false, reason: "connection_mismatch" };
	}
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
		"name_intent",
		() =>
			deps.grantStore.nameIntent({
				grantId: grant.id,
				intent: { handle, expiresAt: record.expiresAt },
				now: now(),
			}),
		() => deps.grantStore.isCurrentIntent(grant.id, handle, now()),
	);
	if (named.landed) {
		return absorbing<FederationGrantReauthorizationResult>(
			{
				ok: true,
				grantId: grant.id,
				handle,
				intentExpiresAt: record.expiresAt,
				lifetimeMs: checked.lifetimeMs,
				connection: connection.name,
				scopes: record.scopes,
				...(record.resource === undefined ? {} : { resource: record.resource }),
				status: judged.admitted,
			},
			named.absorbed,
		);
	}

	const closed = await close(deps.intentStore, handle, now());
	// The pointer write lost: the grant changed under this request. What it is
	// NOW is the answer — never a retry on the strength of the stale reading,
	// which could renew a grant revoked in between. Whatever that answer is,
	// the store errors it does not stand for ride on it (`absorbed`), so that
	// the route reports them: the pointer write's own error, where the re-read
	// decided instead; the question that could not be asked; and an intent
	// that could not be closed, which can activate nothing and lapses with the
	// flow budget.
	const writeThrew: FederationGrantLodgingStepFailure[] =
		"error" in named.why
			? [{ store: "federation_grant", step: "name_intent", error: named.why.error }]
			: [];
	const after = [...named.absorbed, ...leftOpen(closed)];
	let fresh: Awaited<ReturnType<FederationGrantStore["inspect"]>>;
	try {
		fresh = await deps.grantStore.inspect(grant.id, now());
	} catch (error) {
		return absorbing(storage({ store: "federation_grant", step: "inspect", error }), [
			...writeThrew,
			...after,
		]);
	}
	if (fresh === null) {
		return absorbing<ReauthorizationRefusal>({ ok: false, reason: "grant_not_found" }, [
			...writeThrew,
			...after,
		]);
	}
	// Still renewable: the write lost to something that left it so, and the
	// honest answer is that this attempt did not take — with the write's own
	// error as what failed.
	const again = admission(statusOf(deps, fresh, boundary, now()), fresh.grant.connection);
	return "refused" in again
		? absorbing(again.refused, [...writeThrew, ...after])
		: absorbing(storage({ store: "federation_grant", step: "name_intent", ...named.why }), after);
}
