import type { Back, IntentRef } from "@mod/federation-grants";
import { type HttpRequest, type HttpResponse, jsonAnswer, noStore } from "@mod/http";
import { isUnavailable } from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import {
	type DelegatedExchange,
	type Delegation,
	type DelegationStart,
	UpstreamRefused,
} from "@mod/upstreams";

import type { ConnectParts } from "./connect.ts";

export const plain = (status: number, text: string): HttpResponse => ({
	status,
	headers: {
		...noStore,
		"content-type": "text/plain; charset=utf-8",
		"referrer-policy": "no-referrer",
	},
	body: text,
});
export const json = (status: number, body: unknown): HttpResponse =>
	jsonAnswer(status, body, { headers: { "referrer-policy": "no-referrer" } });
export const see = (location: string): HttpResponse => ({
	status: 303,
	headers: { ...noStore, location, "referrer-policy": "no-referrer" },
});
export const stale = () =>
	plain(400, "This request has expired or has already been used. Start again.");
/** Each connection's round trip, by the name its cookie takes. */
export const tripName = (connection: string) => `federation-grants.${connection}`;
export const withCookies = (answer: HttpResponse, cookies: readonly string[]): HttpResponse => ({
	...answer,
	cookies: [...(answer.cookies ?? []), ...cookies],
});
export const invalid = () =>
	json(400, { error: "invalid_request", error_description: "the request is not valid" });
/** Where the intents send the browser back, or the stale answer where they send it nowhere. */
export const backTo = (back: Back) => (back.kind === "back" ? see(back.location) : stale());
/** The request's source, as the audit takes it. */
export const sourceOf = (request: HttpRequest) => {
	const source = determinedSource(request);
	return source ? { source } : {};
};

/** A start as the upstream takes it: where to send the browser, refused as a value, or not askable now. */
export const startOf = (delegation: Delegation | undefined, start: DelegationStart) => {
	try {
		const built = delegation?.authorizationUrl(start);
		if (built === undefined) return { kind: "unavailable" } as const;
		return typeof built === "string"
			? ({ kind: "url", location: built } as const)
			: ({ kind: "refused" } as const);
	} catch {
		// A start the type throws at cannot be asked now; never a 500.
		return { kind: "unavailable" } as const;
	}
};

/** The upstream's login for a code, or the error the browser is sent back with. */
export const exchangedBy = async (delegation: Delegation, exchange: DelegatedExchange) => {
	try {
		return { kind: "login", login: await delegation.exchange(exchange) } as const;
	} catch (error) {
		if (isUnavailable(error)) return { kind: "failed", error: "temporarily_unavailable" } as const;
		if (UpstreamRefused.is(error)) return { kind: "failed", error: "upstream_error" } as const;
		throw error;
	}
};

/** The browser half: the link a client sends the user to, the question, the user's decision, and the upstream's callback. */
/** What every handler of the browser half works with: the session entered as the intent's subject, a question asked, and an intent failed. */
export function connectCommonWith(p: ConnectParts) {
	const { intents, settings } = p;
	/** The session at use level, as the intent's subject; a short one is told whose it is first. */
	const entered = async (request: HttpRequest, subject: string) => {
		const other = { kind: "other" } as const;
		const entry = await p.sessions.enterFor(request, "use");
		if (entry.kind === "entered") return entry.session.context.subject === subject ? entry : other;
		if (entry.kind !== "short") return entry;
		// A short entry names no subject: the level that grants nothing tells whose session it is.
		const bare = await p.sessions.enterFor(request, "none");
		if (bare.kind !== "entered") return { kind: "unknown" } as const;
		const { context } = bare.session;
		return context.subject === subject ? { ...entry, context } : other;
	};
	/** A question still open, asked of this browser's session for the intent's subject. */
	const asked = async (request: HttpRequest, challenge: string) => {
		const found = await intents.asked(challenge);
		if (found.kind !== "asked") return { kind: "refused", answer: invalid() } as const;
		const entry = await entered(request, found.view.subject);
		if (entry.kind === "absent") {
			return {
				kind: "refused",
				answer: json(401, {
					error: "login_required",
					error_description: "no authenticated session",
				}),
			} as const;
		}
		if (entry.kind !== "entered" || entry.session.id !== found.view.session) {
			return {
				kind: "refused",
				answer: json(403, {
					error: "reauthentication_required",
					error_description: "sign in again to continue",
				}),
			} as const;
		}
		if (!(await intents.permitted(found.ref))) {
			return {
				kind: "refused",
				answer: json(403, {
					error: "access_denied",
					error_description: "connection_not_permitted",
				}),
			} as const;
		}
		return found;
	};
	/** Ends the intent with why, audited, and sends the browser back with the error, if the client still lists the return. */
	const fail = async (
		request: HttpRequest,
		ref: IntentRef,
		error: string,
		outcome?: string,
	): Promise<HttpResponse> =>
		backTo(
			await intents.failed(ref, error, {
				...(outcome === undefined ? {} : { outcome }),
				...sourceOf(request),
			}),
		);
	return { p, intents, settings, entered, asked, fail };
}

export type ConnectCommon = ReturnType<typeof connectCommonWith>;
