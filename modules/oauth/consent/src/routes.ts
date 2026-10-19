import { audit, declaredAudit } from "@mod/audit";
import { clients } from "@mod/clients";
import { csrfChecked } from "@mod/csrf";
import type { HttpRequest, HttpResponse, Route } from "@mod/http";
import { jsonAnswer, noStore, use } from "@mod/http";
import { type BuildContext, isUnavailable } from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import { sessions } from "@mod/session";
import { askKey, pendingOf, storedOf } from "./ask.ts";
import events from "./audit-events.ts";
import { shownOf } from "./client-section.ts";
import { consents } from "./contract.ts";
import { askStore } from "./store.ts";

const challengeShape = /^[A-Za-z0-9_-]{43}$/;
/** The challenge if it has the shape consent hands out. */
const challengeIn = (value: string | undefined) =>
	value !== undefined && challengeShape.test(value) ? value : undefined;
function guarded(handle: (request: HttpRequest) => Promise<HttpResponse>) {
	return async (request: HttpRequest): Promise<HttpResponse> => {
		try {
			return await handle(request);
		} catch (error) {
			if (isUnavailable(error)) return jsonAnswer(503, { error: "temporarily_unavailable" });
			throw error;
		}
	};
}

/** `GET /oauth/consent`: what the page shows of the session's pending consent. */
export async function showRoute(c: BuildContext<unknown>): Promise<Route> {
	const opened = await c.get(sessions);
	const asks = await c.get(askStore);
	const given = await c.get(consents);
	const listed = await c.get(clients);
	return {
		method: "GET",
		path: "/oauth/consent",
		changesState: false,
		handle: guarded(async (request) => {
			const session = await opened.enter(request);
			if (!session) return jsonAnswer(401, { error: "no_session" });
			const challenge = challengeIn(request.query.single("challenge"));
			if (!challenge) return jsonAnswer(400, { error: "unknown_challenge" });
			const pending = pendingOf(await asks.read(askKey(session.id, challenge)));
			const now = c.clock.now();
			if (!pending || pending.answer || pending.deadline <= now)
				return jsonAnswer(400, { error: "unknown_challenge" });
			const client = await listed.find(pending.clientId);
			if (!client) return jsonAnswer(400, { error: "unknown_challenge" });
			const { name, uri, host } = shownOf(client);
			return jsonAnswer(200, {
				client_id: pending.clientId,
				...(host === undefined ? {} : { client_id_host: host }),
				...(name === undefined ? {} : { client_name: name }),
				...(uri === undefined ? {} : { client_uri: uri }),
				scopes: pending.range,
				granted_scopes: await given.granted(pending.clientId, pending.subject),
				expires_in: Math.ceil((pending.deadline - now) / 1000),
			});
		}),
	};
}

/** `POST /oauth/consent`: the user's decision on the session's pending consent. */
export async function answerRoute(c: BuildContext<unknown>): Promise<Route> {
	const opened = await c.get(sessions);
	const asks = await c.get(askStore);
	const given = await c.get(consents);
	const recorded = await c.get(audit);
	return {
		method: "POST",
		path: "/oauth/consent",
		uses: [use(csrfChecked)],
		unlimited:
			"The user's session is authenticated; a per-source limit belongs to unauthenticated entries.",
		takes: ["form", "json"],
		handle: guarded(async (request) => {
			if (request.fields.repeated().length > 0) {
				return jsonAnswer(400, { error: "repeated_parameter" });
			}
			const decision = request.fields.single("decision");
			if (decision !== "accept" && decision !== "deny")
				return jsonAnswer(400, { error: "invalid_decision" });
			const session = await opened.enter(request);
			if (!session) return jsonAnswer(401, { error: "no_session" });
			const challenge = challengeIn(request.fields.single("challenge"));
			if (!challenge) return jsonAnswer(400, { error: "unknown_challenge" });
			// The pending consent keeps its answer: a resend of this decision gets the same back, the other none.
			const now = c.clock.now();
			const marked = await asks.update(askKey(session.id, challenge), (record) => {
				const held = pendingOf(record);
				return held.answer ? undefined : { value: storedOf({ ...held, answer: decision }) };
			});
			const pending = pendingOf(marked?.after);
			if (!pending || pending.answer !== decision || pending.deadline <= now)
				return jsonAnswer(400, { error: "unknown_challenge" });
			if (decision === "accept")
				await given.grant(pending.clientId, pending.subject, pending.range);
			// A resend that completes the same decision again is recorded again.
			const source = determinedSource(request);
			declaredAudit(recorded, events).record(
				decision === "accept" ? "consent.granted" : "consent.denied",
				{
					subject: pending.subject,
					attributes: {
						client: pending.clientId,
						...(source === undefined ? {} : { source }),
						scopes: pending.range.join(" "),
					},
				},
			);
			return {
				status: 303,
				headers: {
					...noStore,
					location: decision === "accept" ? pending.onAccept : pending.onDeny,
				},
			};
		}),
	};
}
