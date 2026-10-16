import { type Audit, audit } from "@mod/audit";
import { type Clients, clients } from "@mod/clients";
import { type TargetRule, targets } from "@mod/grants";
import type { HttpRequest, HttpResponse } from "@mod/http";
import { noStore, site } from "@mod/http";
import { issuer as named } from "@mod/issuer";
import { type BuildContext, isUnavailable, type Log, type Unavailable } from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import { answeringUnavailable, oauthError } from "@mod/token-endpoint";
import { redirects } from "../contract.ts";
import { type Decision, refusal } from "../decision.ts";
import { type Flow, flowOver, type Place } from "../flow/flow.ts";
import { answerTo, matches } from "../redirect-uris/redirect-uris.ts";
import type { Settings } from "../section.ts";

export const path = "/oauth/authorize";

/** Length limits: state is echoed back, so it is kept short enough for any Location header. */
const maxValue = 2048;
const maxState = 512;
const found = (status: number, location: string): HttpResponse => ({
	status,
	headers: { ...noStore, location },
});

export interface RouteParts extends Place {
	readonly clients: Pick<Clients, "find">;
	readonly audit: Pick<Audit, "record">;
	readonly flow: Flow;
	readonly log: Log;
	/** The composed rule for the audience a request asks for, which may answer a repeated parameter it reads. */
	readonly rule: Pick<TargetRule, "repeated">;
}

/** Answers both methods of the endpoint. */
export function routeWith({
	issuer,
	self,
	clients: known,
	audit: audited,
	flow,
	log,
	rule,
}: RouteParts): (request: HttpRequest) => Promise<HttpResponse> {
	const warned = ({ what }: Unavailable) =>
		log.warn("authorize.unavailable", { what, route: path });
	const urlWith = (params: Iterable<readonly [string, string]>) =>
		`${self}?${new URLSearchParams([...params].map(([k, v]) => [k, v]))}`;

	const answer = async (request: HttpRequest): Promise<HttpResponse> => {
		if (request.method === "POST") {
			return found(
				303,
				urlWith(
					[...request.form].flatMap(([name, values]) => values.map((v) => [name, v] as const)),
				),
			);
		}
		const source = request.query;
		const repeated = source.repeated();
		const tooLong = [...source]
			.filter(([, values]) => values.some((v) => v.length > maxValue))
			.map(([name]) => name);
		const one = (name: string) => (tooLong.includes(name) ? undefined : source.single(name));

		const clientId = one("client_id");
		if (!clientId) return oauthError(400, "invalid_request", "client_id is required once");
		const client = await known.find(clientId);
		if (!client) return oauthError(400, "invalid_client");
		const redirectUri = one("redirect_uri");
		const registered = client.section(redirects)["redirect-uris"];
		if (!redirectUri || !registered.some((r) => matches(r, redirectUri))) {
			return oauthError(400, "invalid_request", "redirect_uri is not registered for the client");
		}

		// From here on the redirect URI is trusted, and every answer goes back to it.
		const stateText = one("state");
		const state = stateText !== undefined && stateText.length <= maxState ? stateText : undefined;
		const back = (params: Record<string, string>) =>
			answerTo(redirectUri, { ...params, state, iss: issuer });
		const reply = (d: Decision) =>
			found(
				302,
				d.kind === "send"
					? d.to
					: back(
							d.kind === "code"
								? { code: d.code }
								: {
										error: d.error,
										...(d.description ? { error_description: d.description } : {}),
									},
						),
			);
		if (repeated.length > 0) {
			// A parameter the rule reads, sent twice, is the rule's to answer (RFC 8707 §2's invalid_target).
			const ruled = repeated.map((name) => rule.repeated?.(name)).find((r) => r !== undefined);
			return reply(
				ruled
					? refusal(ruled.error, ruled.description)
					: refusal("invalid_request", "repeated parameter"),
			);
		}
		if (tooLong.length > 0 || (stateText !== undefined && state === undefined)) {
			return reply(refusal("invalid_request", "parameter too long"));
		}
		const params = new Map([...source].map(([name, values]) => [name, values[0] ?? ""]));
		const from = determinedSource(request);
		const by = { client: client.id, ...(from === undefined ? {} : { source: from }) };
		try {
			const decided = await flow({ client, redirectUri, one, params, request });
			if (decided.kind === "code") {
				const attributes = { ...by, response_type: "code" };
				audited.record({ kind: "authorize.granted", subject: decided.subject, attributes });
			}
			if (decided.kind === "refuse" && decided.reason !== undefined) {
				const { reason, policy } = decided;
				const attributes = { ...by, reason, ...(policy === undefined ? {} : { policy }) };
				audited.record({ kind: "authorize.rejected", attributes });
			}
			return reply(decided);
		} catch (error) {
			if (!isUnavailable(error)) throw error;
			warned(error);
			return reply(refusal("temporarily_unavailable"));
		}
	};
	return answeringUnavailable(answer, (_request, unavailable) => warned(unavailable));
}

/** This endpoint's URL on `http`'s public origin; none without one. */
export const endpointOver = async (c: BuildContext<Settings>) => {
	const origin = (await c.get(site)).origin;
	return origin && `${origin}${path}`;
};

/** The handler over the contracts the assembly gives; refuses to start without a public origin. */
export async function routeOver(c: BuildContext<Settings>) {
	const self = await endpointOver(c);
	if (self === undefined) return c.refuse("authorize", "a public origin is required");
	const place = { issuer: (await c.get(named)).url, self };
	return routeWith({
		...place,
		clients: await c.get(clients),
		audit: await c.get(audit),
		flow: await flowOver(c, place),
		log: c.log,
		rule: await c.get(targets),
	});
}
