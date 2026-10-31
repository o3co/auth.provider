import type { Client } from "@mod/clients";
import type { HttpRequest, HttpResponse } from "@mod/http";
import { isUnavailable } from "@mod/kernel";
import { type Grant, withoutCredentials } from "../../grant/grant.ts";
import { type Body, bodyOf } from "../body.ts";
import { type ApiCommon, error } from "../common.ts";

/** One answer, byte for byte, for an unknown grant and another client's or subject's. */
const notFound = () => error(404, "grant_not_found");
/** The routes a grant answers once owned. */
export interface Handlers {
	readonly reauthorize: ById["handle"];
	readonly token: ById["handle"];
	readonly status: (client: Client, grant: Grant) => HttpResponse;
	readonly revoke: (request: HttpRequest, client: Client, grant: Grant) => Promise<HttpResponse>;
}

/** A route a grant answers by id: the names its body takes, and how it is answered once owned. */
export interface ById {
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

/** A grant's routes by id: who owns it judged first, then its boundary and its end, then the route. */
export function routingWith(
	{ p, records, secret, record }: ApiCommon,
	{ reauthorize, token, status, revoke }: Handlers,
) {
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
	return { byId };
}
