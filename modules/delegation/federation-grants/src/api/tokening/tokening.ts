import type { Client } from "@mod/clients";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { isUnavailable } from "@mod/kernel";
import { type Grant, permits, scopeTokens, within } from "../../grant/grant.ts";
import type { Current } from "../../refresh/refresh.ts";
import type { Body } from "../body.ts";
import { type ApiCommon, error } from "../common.ts";

const iso = (ms: number | undefined) => (ms === undefined ? undefined : new Date(ms).toISOString());

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

/** A grant's token handed, its use noted, and its status as the client asks it. */
export function tokeningWith({ p, records, connections, record, stateRefusal }: ApiCommon) {
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
	return { token, status };
}
