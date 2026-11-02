import type { Client } from "@mod/clients";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import {
	type Grant,
	type Intent,
	permits,
	retentionMs,
	returnsTo,
	scopeTokens,
	within,
} from "../../grant/grant.ts";
import type { Connection } from "../../section.ts";
import { type Body, bodyOf } from "../body.ts";
import { type ApiCommon, error } from "../common.ts";

/** A grant lodged, or a renewal of one, each an intent and the link a browser opens to connect. */
export function lodgingWith({
	p,
	records,
	settings,
	secret,
	connections,
	record,
	stateRefusal,
}: ApiCommon) {
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
	return { lodge, reauthorize };
}
