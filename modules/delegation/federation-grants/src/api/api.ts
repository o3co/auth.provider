import { type Audit, audit, declaredAudit } from "@mod/audit";
import { type Client, type Clients, clients, recordRefusedAuthentication } from "@mod/clients";
import { type HttpRequest, type HttpResponse, jsonAnswer, noStore } from "@mod/http";
import { type BuildContext, type Clock, isUnavailable, type Random } from "@mod/kernel";
import { attemptLimit, type RateLimit } from "@mod/rate-limit";
import { determinedSource } from "@mod/request-source";
import { type Upstreams, upstreams } from "@mod/upstreams";
import events from "../audit-events.ts";
import {
	connectionsIn,
	type Grant,
	type Intent,
	type Judge,
	type Listing,
	permits,
	type Records,
	retentionMs,
	returnsTo,
	scopeTokens,
	secretFrom,
	within,
	withoutCredentials,
} from "../grant/grant.ts";
import { shared } from "../grant/shared.ts";
import { type Current, type Refresh, refreshOver, refreshTakes } from "../refresh/refresh.ts";
import type { Connection, Settings } from "../section.ts";
import {
	type GrantStore,
	grantStore,
	type PendingIntents,
	pendingIntents,
	type StepStore,
	stepStore,
} from "../store.ts";
import { type Body, bodyOf } from "./body.ts";

export interface ApiParts {
	readonly clients: Clients;
	readonly grants: GrantStore;
	readonly steps: StepStore;
	readonly pending: PendingIntents;
	readonly lodges: RateLimit;
	readonly records: Records;
	readonly judge: Judge;
	readonly listed: Listing;
	readonly refresh: Refresh;
	readonly upstreams: Upstreams;
	readonly audit: Audit;
	readonly settings: Settings;
	readonly origin: string;
	readonly clock: Clock;
	readonly random: Random;
}

export const base = "/oauth/federation-grants";

const error = (
	status: number,
	code: string,
	description?: string,
	headers?: Record<string, string>,
) =>
	jsonAnswer(
		status,
		{ error: code, ...(description ? { error_description: description } : {}) },
		headers ? { headers } : {},
	);
/** One answer, byte for byte, for an unknown grant and another client's or subject's. */
const notFound = () => error(404, "grant_not_found");
const iso = (ms: number | undefined) => (ms === undefined ? undefined : new Date(ms).toISOString());
/** The most characters of a text a caller sent that reach audit: federation-grants' own cap. */
const auditTextMax = 200;
/** Text a caller sent, cut short before it reaches audit. */
const cut = (text: string) => text.slice(0, auditTextMax);

/** The status, word and audited reason each outcome of a token request short of a token is answered with. */
const refusals: Record<
	Exclude<Current["kind"], "handed" | "limited">,
	readonly [number, string, string]
> = {
	reauthorize: [410, "reauthorization_required", "reauthorization_required"],
	ineligible: [502, "upstream_token_ineligible", "upstream_token_ineligible"],
	refused: [502, "upstream_rejected", "upstream_rejected"],
	scope: [400, "invalid_scope", "invalid_scope"],
	unavailable: [503, "temporarily_unavailable", "upstream_unavailable"],
	lock_timeout: [503, "temporarily_unavailable", "lock_timeout"],
	gone: [503, "temporarily_unavailable", "grant_changed"],
};

/** The client routes: lodging an intent, renewing a grant, and a grant's token, status and revocation. */
export function apiWith(p: ApiParts) {
	const { records, settings } = p;
	const secret = secretFrom(p.random);
	const connections = connectionsIn(settings, p.upstreams);
	const audited = declaredAudit(p.audit, events);
	const record = (
		kind: keyof typeof events,
		subject: string | undefined,
		attributes: Record<string, string>,
		request: HttpRequest,
	) => {
		const from = determinedSource(request);
		audited.record(kind, {
			...(subject === undefined ? {} : { subject: cut(subject) }),
			attributes: { ...attributes, ...(from ? { source: from } : {}) },
		});
	};

	/** The grant when it is this client's and this subject's; none for any other, alike. */
	const owned = async (id: string, client: Client, subject: string) => {
		const grant = records.grantOf(await p.grants.read(id));
		return grant?.client === client.id && grant.subject === subject ? grant : undefined;
	};
	/**
	 * Ends a grant a subject's revocation covers, writing it, before anything else is asked of it;
	 * `ended` only when this request's write ended it. A grant gone meanwhile is answered as ended.
	 */
	const backstop = async (grant: Grant) => {
		if (grant.status === "revoked" || !(await p.judge.revoked(grant))) {
			return { grant, ended: false };
		}
		const revoked = (g: Grant): Grant => ({
			...withoutCredentials(g),
			status: "revoked",
			reason: "backstop",
		});
		const changed = await p.grants.change(grant.id, (stored) => {
			const now = records.grantOf(stored);
			if (!now || now.status === "revoked") return undefined;
			return { value: records.stored(revoked(now)) };
		});
		const after = records.grantOf(changed?.after);
		const ended = records.grantOf(changed?.before)?.status !== "revoked" && after !== undefined;
		return { grant: after ?? revoked(grant), ended };
	};
	/** Erases the credentials of a grant past its end (its own, or the longest life allowed now); its status stays to be answered. */
	const lapse = async (grant: Grant): Promise<Grant> => {
		const at = p.clock.now();
		const over = (g: Grant) => {
			const end = p.judge.endOf(g);
			return g.sealed !== undefined && end !== undefined && end <= at;
		};
		if (!over(grant)) return grant;
		const changed = await p.grants.change(grant.id, (stored) => {
			const now = records.grantOf(stored);
			// A new version, so a refresh that read the grant before cannot write credentials back.
			return now && over(now)
				? { value: records.stored({ ...withoutCredentials(now), version: secret() }) }
				: undefined;
		});
		return records.grantOf(changed?.after) ?? grant;
	};

	/** An intent from a lodging's or a renewal's body, or the refusal that answers it. */
	const intentFrom = (
		body: Extract<Body, { kind: "read" }>,
		client: Client,
		connection: Connection,
		kind: Intent["kind"],
	):
		| { readonly kind: "refused"; readonly answer: HttpResponse }
		| { readonly kind: "intent"; readonly intent: Intent } => {
		const refused = (code: string, description: string) =>
			({ kind: "refused", answer: error(400, code, description) }) as const;
		const returnUri = body.text("redirect_uri");
		const state = body.text("state");
		if (!returnUri) return refused("invalid_request", "redirect_uri_required");
		if (state === undefined) return refused("invalid_request", "state_required");
		if (!returnsTo(client, returnUri))
			return refused("invalid_request", "redirect_uri_not_registered");
		const asked = body.text("scope");
		const scopes = asked === undefined ? connection.scopes : scopeTokens(asked);
		if (!scopes) return refused("invalid_request", "invalid_scope");
		if (!within(scopes, connection.scopes)) return refused("invalid_scope", "scope_exceeded");
		if (!scopes.includes("openid")) return refused("invalid_scope", "openid_required");
		if (connection.scopes.includes("offline_access") && !scopes.includes("offline_access")) {
			return refused("invalid_scope", "offline_access_required");
		}
		if (!connection["scope-subsets"] && !within(connection.scopes, scopes)) {
			return refused("invalid_scope", "scope_subsets_not_allowed");
		}
		const seconds = body.number("expires_in");
		if (seconds === 0) return refused("invalid_request", "invalid_expires_in");
		const lifetimeMs =
			Math.min(seconds ?? settings["default-lifetime"], settings["max-lifetime"]) * 1000;
		const expectedUpstream = body.text("upstream_sub");
		const now = p.clock.now();
		const intent: Intent = {
			id: secret(),
			kind,
			returnUri,
			state,
			scopes,
			lifetimeMs,
			...(expectedUpstream ? { expectedUpstream } : {}),
			startedAt: now,
			endsAt: now + settings["connect-lifetime"] * 1000,
		};
		return { kind: "intent", intent };
	};
	/** Keeps the link a browser opens to connect, and answers where to send it. */
	const linked = async (grant: Grant, intent: Intent, status: string) => {
		const handle = secret();
		const step = records.storedStep({
			format: 1,
			kind: "link",
			grant: grant.id,
			intent: intent.id,
		});
		await p.steps.create(handle, step, settings["connect-lifetime"] * 1000);
		return jsonAnswer(201, {
			grant_id: grant.id,
			status,
			connect_uri: `${p.origin}/session/federation-grants/connect?request=${handle}`,
			connect_expires_in: settings["connect-lifetime"],
			expires_in: intent.lifetimeMs / 1000,
		});
	};

	/** Ends a grant's current intent with why, unless it ended already. */
	const endIntent = (id: string, why: string) =>
		p.grants.change(id, (stored) => {
			const grant = records.grantOf(stored);
			if (!grant?.intent || grant.intent.ended) return undefined;
			return { value: records.stored({ ...grant, intent: { ...grant.intent, ended: why } }) };
		});

	/** How many intents, lodged or renewed, one client may write in a window. */
	const lodgeWindow = () => ({ limit: settings.lodges, ms: settings["lodge-window"] * 1000 });

	const lodge = async (request: HttpRequest, client: Client): Promise<HttpResponse> => {
		const body = bodyOf(
			request,
			["connection", "sub", "redirect_uri", "state", "scope", "upstream_sub"],
			["expires_in"],
		);
		if (body.kind === "refused") return error(400, "invalid_request", body.description);
		const subject = body.text("sub");
		const name = body.text("connection");
		if (!subject) return error(400, "invalid_request", "sub_required");
		if (!name) return error(400, "invalid_request", "connection_required");
		const denied = (outcome: string) => {
			record("federation.grant.request.denied", subject, { client: client.id, outcome }, request);
		};
		if (!permits(client, name)) {
			denied("connection_not_permitted");
			return error(403, "access_denied", "connection_not_permitted");
		}
		const configured = connections.configured(name);
		if (!configured) return error(503, "temporarily_unavailable", "connection_not_configured");
		const asked = intentFrom(body, client, configured.connection, "initial");
		if (asked.kind === "refused") {
			denied("invalid_request");
			return asked.answer;
		}
		const { intent } = asked;
		// Counted per client, whatever subject it names, so no client fills the store.
		const counted = await p.lodges.hit("federation-grants.lodges", client.id, lodgeWindow());
		if (counted.kind === "limited") {
			denied("rate_limited");
			const after = String(Math.ceil(counted.retryAfterMs / 1000));
			return error(429, "rate_limited", "provider", { "retry-after": after });
		}
		const now = p.clock.now();
		const grant: Grant = {
			format: 1,
			id: secret(),
			client: client.id,
			subject,
			connection: name,
			status: "pending",
			createdAt: now,
			scopes: intent.scopes,
			intent,
			version: secret(),
			rotations: { from: now, count: 0 },
		};
		const connectMs = settings["connect-lifetime"] * 1000;
		await p.grants.create(grant.id, records.stored(grant), connectMs + retentionMs);
		await p.listed(grant, connectMs);
		// Past the pair's cap, the intents that end first are pushed out, and end.
		const { pushedOut } = await p.pending.add(`${client.id}\n${subject}`, grant.id, connectMs);
		for (const id of pushedOut) await endIntent(id, "pushed_out");
		record(
			"federation.grant.requested",
			subject,
			{ client: client.id, connection: name, outcome: "initial" },
			request,
		);
		return linked(grant, intent, "pending");
	};

	/** What a grant's own record says before anything is asked of it, as every grant route answers it, and why. */
	const stateRefusal = (
		grant: Grant,
	): { readonly why: string; readonly answer: HttpResponse } | undefined => {
		if (grant.status === "revoked")
			return { why: "grant_revoked", answer: error(410, "grant_revoked", grant.reason) };
		if (grant.status === "pending")
			return { why: "authorization_pending", answer: error(400, "authorization_pending") };
		const end = p.judge.endOf(grant);
		if (end !== undefined && end <= p.clock.now())
			return { why: "grant_expired", answer: error(410, "grant_expired", "lifetime") };
		return undefined;
	};

	const reauthorize = async (
		request: HttpRequest,
		client: Client,
		grant: Grant,
		body: Extract<Body, { kind: "read" }>,
	) => {
		const refused = stateRefusal(grant);
		if (refused) return refused.answer;
		const configured = connections.configured(grant.connection);
		if (!permits(client, grant.connection) || !configured) {
			return error(403, "access_denied", "connection_not_permitted");
		}
		const named = body.text("connection");
		if (named !== undefined && named !== grant.connection)
			return error(400, "invalid_request", "connection_mismatch");
		if (grant.status === "upstream_token_ineligible" && grant.reason !== "scope_exceeded") {
			return error(502, "upstream_token_ineligible", grant.reason);
		}
		const asked = intentFrom(body, client, configured.connection, "reauthorization");
		if (asked.kind === "refused") return asked.answer;
		const { intent } = asked;
		// Counted with the client's lodgings: each renewal writes an intent and a link too.
		const counted = await p.lodges.hit("federation-grants.lodges", client.id, lodgeWindow());
		if (counted.kind === "limited") {
			record(
				"federation.grant.request.denied",
				grant.subject,
				{ client: client.id, outcome: "rate_limited" },
				request,
			);
			const after = String(Math.ceil(counted.retryAfterMs / 1000));
			return error(429, "rate_limited", "provider", { "retry-after": after });
		}
		const changed = await p.grants.change(grant.id, (stored) => {
			const now = records.grantOf(stored);
			if (now?.status === "revoked" || now?.status === "pending" || !now) return undefined;
			return { value: records.stored({ ...now, intent }) };
		});
		const renewed = records.grantOf(changed?.after);
		if (renewed?.intent?.id !== intent.id) return error(503, "temporarily_unavailable");
		record(
			"federation.grant.requested",
			grant.subject,
			{ client: client.id, connection: grant.connection, outcome: "reauthorization" },
			request,
		);
		return linked(renewed, intent, renewed.status);
	};

	const token = async (
		request: HttpRequest,
		client: Client,
		grant: Grant,
		body: Extract<Body, { kind: "read" }>,
	) => {
		/** Audits the refusal by why, and answers it. */
		const refuse = (why: string, refusal: HttpResponse) => {
			record(
				"federation.grant.token.denied",
				grant.subject,
				{ client: client.id, connection: grant.connection, reason: why },
				request,
			);
			return refusal;
		};
		const refused = stateRefusal(grant);
		if (refused) return refuse(refused.why, refused.answer);
		if (grant.status === "reauthorization_required") {
			const refusal = error(410, "reauthorization_required", grant.reason);
			return refuse("reauthorization_required", refusal);
		}
		const configured = connections.configured(grant.connection);
		if (!permits(client, grant.connection) || !configured) {
			const refusal = error(403, "access_denied", "connection_not_permitted");
			return refuse("connection_not_permitted", refusal);
		}
		const { connection, delegation } = configured;
		const named = body.text("connection");
		if (named !== undefined && named !== grant.connection)
			return refuse("connection_mismatch", error(400, "invalid_request", "connection_mismatch"));
		const resource = body.text("resource");
		if (resource !== undefined && resource !== connection.resource)
			return refuse("invalid_target", error(400, "invalid_target"));
		const asked = body.text("scope");
		const scope = asked === undefined ? undefined : scopeTokens(asked);
		if ((asked !== undefined && !scope) || (scope && !within(scope, grant.scopes)))
			return refuse("invalid_scope", error(400, "invalid_scope"));
		const minTtl = body.number("min_ttl") ?? 0;
		const maxAccessMs = connection["max-access-token-lifetime"] * 1000;
		if (minTtl * 1000 > maxAccessMs) {
			const refusal = error(400, "invalid_request", "min_ttl_out_of_range");
			return refuse("min_ttl_out_of_range", refusal);
		}
		const current = await p.refresh.current(grant, {
			delegation,
			...(connection.resource ? { resource: connection.resource } : {}),
			maxAccessMs,
			...(scope ? { scope } : {}),
			minTtlMs: minTtl * 1000,
			grantEndsAt: p.judge.endOf(grant) ?? p.clock.now(),
		});
		if (current.kind === "handed") {
			await used(grant);
			record(
				"federation.grant.token.success",
				grant.subject,
				{ client: client.id, connection: grant.connection, refreshed: String(current.refreshed) },
				request,
			);
			return jsonAnswer(200, {
				access_token: current.accessToken,
				token_type: current.tokenType,
				expires_in: current.expiresInSeconds,
				scope: current.scope.join(" "),
			});
		}
		if (current.kind === "limited") {
			const after = current.retryAfterSeconds;
			const headers = after === undefined ? {} : { "retry-after": String(after) };
			return refuse("rate_limited", error(429, "rate_limited", "provider", headers));
		}
		const [status, code, said] = refusals[current.kind];
		const description =
			"reason" in current ? current.reason : current.kind === "refused" ? "unknown" : undefined;
		const headers = status === 502 ? { "retry-after": "300" } : {};
		return refuse(
			"reason" in current ? current.reason : said,
			error(status, code, description, headers),
		);
	};

	/** Notes when an active grant's token was handed out, never moving it back; a use that cannot be noted is still a use. */
	const used = async (grant: Grant) => {
		const at = p.clock.now();
		try {
			await p.grants.change(grant.id, (stored) => {
				const now = records.grantOf(stored);
				if (now?.status !== "active" || (now.lastUsedAt ?? 0) >= at) return undefined;
				return { value: records.stored({ ...now, lastUsedAt: at }) };
			});
		} catch (thrown) {
			if (!isUnavailable(thrown)) throw thrown;
		}
	};

	const status = (client: Client, grant: Grant) => {
		// A pending grant has not started: answering it is still the client's to be allowed.
		if (grant.status === "pending" && !permits(client, grant.connection)) {
			return error(403, "access_denied", "connection_not_permitted");
		}
		const end = p.judge.endOf(grant);
		const over = grant.status !== "revoked" && end !== undefined && end <= p.clock.now();
		return jsonAnswer(200, {
			grant_id: grant.id,
			status: over ? "expired" : grant.status,
			...(grant.reason && !over ? { reason: grant.reason } : {}),
			sub: grant.subject,
			client_id: grant.client,
			connection: grant.connection,
			created_at: iso(grant.createdAt),
			...(grant.upstream ? { upstream: grant.upstream } : {}),
			...(grant.status === "pending" ? {} : { scope: grant.scopes.join(" ") }),
			...(grant.authorizedAt === undefined ? {} : { authorized_at: iso(grant.authorizedAt) }),
			...(end === undefined ? {} : { expires_at: iso(end) }),
			// When it was last used is told only to a client still allowed the connection.
			...(grant.lastUsedAt === undefined || !permits(client, grant.connection)
				? {}
				: { last_used_at: iso(grant.lastUsedAt) }),
		});
	};

	const revoke = async (request: HttpRequest, client: Client, grant: Grant) => {
		const changed = await p.grants.change(grant.id, (stored) => {
			const now = records.grantOf(stored);
			if (!now || now.status === "revoked") return undefined;
			return {
				value: records.stored({ ...withoutCredentials(now), status: "revoked", reason: "client" }),
			};
		});
		if (records.grantOf(changed?.before)?.status !== "revoked" && changed) {
			record(
				"federation.grant.revoked",
				grant.subject,
				{ client: client.id, connection: grant.connection, outcome: "client" },
				request,
			);
		}
		return { status: 204, headers: noStore };
	};

	/** A route a grant answers by id: the names its body takes, and how it is answered once owned. */
	interface ById {
		readonly texts: readonly string[];
		readonly numbers?: readonly string[];
		/** Whether its subject's boundary is judged first; a revocation is answered whatever the state. */
		readonly judged: boolean;
		/** The event each refusal is audited as, if any. */
		readonly denied?: "federation.grant.token.denied" | "federation.grant.revoke.denied";
		readonly handle: (
			request: HttpRequest,
			client: Client,
			grant: Grant,
			body: Extract<Body, { kind: "read" }>,
		) => Promise<HttpResponse> | HttpResponse;
	}
	/** The routes a grant answers by id; each judges who owns it before anything else. */
	const byIdRoutes = new Map<string, ById>([
		[
			"reauthorize",
			{
				texts: ["sub", "connection", "redirect_uri", "state", "scope", "upstream_sub"],
				numbers: ["expires_in"],
				judged: true,
				handle: reauthorize,
			},
		],
		[
			"token",
			{
				texts: ["sub", "scope", "connection", "resource"],
				numbers: ["min_ttl"],
				judged: true,
				denied: "federation.grant.token.denied",
				handle: token,
			},
		],
		["status", { texts: ["sub"], judged: true, handle: (_r, c, grant) => status(c, grant) }],
		[
			"revoke",
			{ texts: ["sub"], judged: false, denied: "federation.grant.revoke.denied", handle: revoke },
		],
	]);
	const byId = async (request: HttpRequest, client: Client, id: string, step: string) => {
		const route = byIdRoutes.get(step);
		if (!route) return error(404, "not_found");
		try {
			return await byRoute(request, client, id, route);
		} catch (thrown) {
			// An outage is audited as the route's refusal, as one answered without throwing is; recording
			// is best effort, and the 503 is answered where every route's is.
			if (isUnavailable(thrown) && route.denied) {
				try {
					record(route.denied, undefined, { client: client.id, reason: "unavailable" }, request);
				} catch {}
			}
			throw thrown;
		}
	};
	const byRoute = async (request: HttpRequest, client: Client, id: string, route: ById) => {
		// Before the grant's owner is known, a refusal is audited by the client only.
		const early = (why: string, refusal: HttpResponse) => {
			if (route.denied) {
				const attributes = { client: client.id, reason: why };
				record(route.denied, undefined, attributes, request);
			}
			return refusal;
		};
		const body = bodyOf(request, route.texts, route.numbers);
		if (body.kind === "refused")
			return early(body.description, error(400, "invalid_request", body.description));
		const subject = body.text("sub");
		if (!subject) return early("sub_required", error(400, "invalid_request", "sub_required"));
		const found = await owned(id, client, subject);
		if (!found) return early("grant_not_found", notFound());
		if (!route.judged) return route.handle(request, client, found, body);
		const backstopped = await backstop(found);
		const grant = await lapse(backstopped.grant);
		if (backstopped.ended) {
			record(
				"federation.grant.revoked",
				grant.subject,
				{ client: client.id, connection: grant.connection, outcome: "backstop" },
				request,
			);
		}
		return route.handle(request, client, grant, body);
	};

	return async (request: HttpRequest): Promise<HttpResponse> => {
		try {
			const authenticated = await p.clients.authenticate(request);
			if (authenticated.kind === "refused")
				recordRefusedAuthentication(p.audit, request, authenticated);
			if (authenticated.kind === "refused" || authenticated.client.kind !== "confidential") {
				const challenges = authenticated.kind === "refused" ? authenticated.challenges : [];
				return error(
					401,
					"invalid_client",
					undefined,
					challenges.length > 0 ? { "www-authenticate": challenges.join(", ") } : {},
				);
			}
			const client = authenticated.client;
			if (request.path === base) return await lodge(request, client);
			const [id = "", step = "", ...rest] = request.path.slice(base.length + 1).split("/");
			if (id === "" || rest.length > 0) return error(404, "not_found");
			return await byId(request, client, id, step);
		} catch (thrown) {
			if (isUnavailable(thrown)) return error(503, "temporarily_unavailable");
			throw thrown;
		}
	};
}

export const apiTakes = [
	...refreshTakes,
	clients,
	grantStore,
	stepStore,
	pendingIntents,
	attemptLimit,
	upstreams,
	audit,
] as const;

/** The client routes' handler, over the contracts the assembly gives. */
export async function apiOver(c: BuildContext<Settings>) {
	const parts = await c.get(shared);
	return apiWith({
		...parts,
		clients: await c.get(clients),
		grants: await c.get(grantStore),
		steps: await c.get(stepStore),
		pending: await c.get(pendingIntents),
		lodges: await c.get(attemptLimit),
		refresh: await refreshOver(c, parts.records, parts.judge),
		upstreams: await c.get(upstreams),
		audit: await c.get(audit),
		settings: c.section,
		clock: c.clock,
		random: c.random,
	});
}
