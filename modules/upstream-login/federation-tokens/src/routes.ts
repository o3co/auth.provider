import { type Audit, declaredAudit } from "@mod/audit";
import type { Client, Clients, Section } from "@mod/clients";
import { type HttpRequest, type HttpResponse, noStore } from "@mod/http";
import { isUnavailable, type Log } from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import type { Upstreams } from "@mod/upstreams";
import { z } from "zod";
import events from "./audit-events.ts";
import type { CallerCheck } from "./caller/caller.ts";
import { endSessionAt } from "./end-session.ts";
import type { Current, Renewal } from "./renewal/renewal.ts";

export const base = "/oauth/federation";

type Kind = keyof typeof events;

/** Client metadata: whether the client may receive upstream tokens, and where an upstream logout may return. */
export const clientSection: Section<{
	readonly receives: boolean;
	readonly "post-logout-redirect-uris": readonly string[];
}> = {
	name: "federation-tokens",
	schema: z.strictObject({
		receives: z.boolean().prefault(false),
		"post-logout-redirect-uris": z.array(z.string().min(1)).prefault([]),
	}),
};

export interface Flow {
	readonly caller: CallerCheck;
	readonly renewal: Renewal;
	readonly clients: Clients;
	readonly upstreams: Upstreams;
	readonly audit: Audit;
	readonly log: Pick<Log, "warn">;
}

const answer = (
	status: number,
	json: unknown,
	headers: Readonly<Record<string, string>> = {},
): HttpResponse => ({ status, headers: { ...noStore, ...headers }, body: { json } });

/** Each outcome short of a token, as the status and error word clients of this route know. */
const refusals: Record<Exclude<Current["kind"], "handed" | "limited">, [number, string]> = {
	not_linked: [404, "federation_not_linked"],
	ineligible: [502, "upstream_token_ineligible"],
	refresh_absent: [410, "refresh_token_absent"],
	reauthenticate: [410, "re_authentication_required"],
	interaction_required: [403, "upstream_interaction_required"],
	failed: [500, "refresh_failed"],
	// The upstream offers no refresh, or the settings no longer hold the IdP: it never will, so log in again.
	not_supported: [410, "refresh_not_supported"],
	lock_timeout: [503, "lock_timeout"],
	unavailable: [503, "temporarily_unavailable"],
};

/** Only an operator's client may be named a receiver. */
const receives = (client: Client | undefined) =>
	client?.registered === true && client.section(clientSection).receives;

/** Answers an IdP's token or logout route under the base path; anything else there is not found. */
export async function federationTokens(flow: Flow, request: HttpRequest): Promise<HttpResponse> {
	const [idp = "", step, ...rest] = request.path.slice(base.length + 1).split("/");
	if (idp === "" || rest.length > 0 || (step !== "token" && step !== "logout")) {
		return answer(404, { error: "not_found" });
	}
	try {
		const caller = await flow.caller.accepted(request);
		if (caller.kind === "refused") {
			const { status, error, headers } = caller;
			return answer(status, error === undefined ? {} : { error }, headers);
		}
		const from = determinedSource(request);
		const record = (kind: Kind, attributes: Record<string, string>) =>
			declaredAudit(flow.audit, events).record(kind, {
				subject: caller.subject,
				attributes: {
					idp,
					client: caller.client,
					...attributes,
					...(from ? { source: from } : {}),
				},
			});
		if (step === "logout") return await logout(flow, request, idp, caller, record);
		if (!receives(await flow.clients.find(caller.client))) {
			record("federation.token.failed", { reason: "forbidden" });
			return answer(403, { error: "forbidden" });
		}
		const current = await flow.renewal.current(caller.session, idp);
		if (current.kind === "limited") {
			const after = current.retryAfterSeconds;
			const said = after !== undefined && Number.isInteger(after) && after >= 1 && after <= 86_400;
			return answer(429, { error: "rate_limited" }, said ? { "retry-after": String(after) } : {});
		}
		if (current.kind !== "handed") {
			const [status, error] = refusals[current.kind];
			if (status !== 503 && status !== 404) {
				record("federation.token.failed", { reason: current.kind });
			}
			return answer(status, { error }, status === 502 ? { "retry-after": "300" } : {});
		}
		// The session may have closed while the upstream answered.
		if (!(await flow.caller.stillOpen(caller))) {
			return answer(
				401,
				{ error: "invalid_token" },
				{
					"www-authenticate": 'Bearer error="invalid_token"',
				},
			);
		}
		record("federation.token.succeeded", { refreshed: String(current.refreshed) });
		return answer(200, {
			access_token: current.accessToken,
			token_type: "Bearer",
			...(current.expiresInSeconds === undefined ? {} : { expires_in: current.expiresInSeconds }),
			...(current.scope.length > 0 ? { scope: current.scope.join(" ") } : {}),
		});
	} catch (error) {
		if (isUnavailable(error)) return answer(503, { error: "temporarily_unavailable" });
		throw error;
	}
}

/** Forgets the session's tokens from the IdP first, then sends the browser to the upstream's end of session. */
async function logout(
	flow: Flow,
	request: HttpRequest,
	idp: string,
	caller: { readonly session: string; readonly client: string },
	record: (kind: Kind, attributes: Record<string, string>) => void,
) {
	const asked = request.form.single("post_logout_redirect_uri");
	const state = request.form.single("state");
	const disconnected = await flow.renewal.disconnect(caller.session, idp);
	if (disconnected.kind === "not_linked") return answer(404, { error: "federation_not_linked" });
	// A return the client did not register, or a client that cannot be read, is dropped quietly.
	const client = await flow.clients.find(caller.client).catch(() => undefined);
	const listed = client?.section(clientSection)["post-logout-redirect-uris"] ?? [];
	const back = asked !== undefined && listed.includes(asked) ? asked : undefined;
	const location = endSessionAt(
		flow.upstreams,
		idp,
		disconnected.idToken,
		{
			...(back ? { postLogoutRedirectUri: back } : {}),
			...(state === undefined ? {} : { state }),
		},
		flow.log,
	);
	record("federation.logout.succeeded", { redirected: String(location !== undefined) });
	if (location === undefined) return answer(200, { disconnected: true });
	return { status: 303, headers: { ...noStore, location } };
}
