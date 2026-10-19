import { createHash } from "node:crypto";
import { type Audit, declaredAudit } from "@mod/audit";
import { type Cookies, cookies } from "@mod/cookies";
import type { HttpRequest, HttpResponse, Site, Values } from "@mod/http";
import { jsonAnswer, noStore, site } from "@mod/http";
import {
	type BuildContext,
	type Clock,
	contract,
	isUnavailable,
	type Log,
	type Random,
	sameSecret,
	Unavailable,
} from "@mod/kernel";
import { type Logins, logins } from "@mod/login-gates";
import { determinedSource } from "@mod/request-source";
import { type Upstream, type UpstreamLogin, UpstreamRefused } from "@mod/upstreams";
import events from "../audit-events.ts";
import type { Settings } from "../section.ts";
import { type TransactionStore, transactionStore } from "../store.ts";
import { fromStored, type Transaction, toStored } from "./transaction.ts";

export const base = "/session/oauth/federation";
/** Each IdP's own callback, named after it, so two never share one. */
export const callbackPath = (idp: string) => `${base}/${idp}/callback`;

/** One configured IdP, opened at boot. */
export interface Idp {
	readonly upstream: Upstream;
	readonly formPost: boolean;
	readonly redirectUri: string;
	readonly upstreamAmr: ReadonlyMap<string, string>;
}

/** What a transaction carries from its start to the continuation that completes it. */
export type Carried = Pick<Transaction, "link">;

/** What the round trip hands a continuation once the upstream's answer is taken, exchanged and fresh. */
export interface Completing {
	readonly request: HttpRequest;
	readonly name: string;
	readonly idp: Idp;
	readonly upstreamLogin: UpstreamLogin;
	readonly transaction: Transaction;
	readonly source?: string;
	readonly userAgent?: string;
	/** The transaction's cookie, cleared: every answer from here on carries it. */
	readonly cleared: readonly string[];
}

/** Where a round trip goes once the upstream answers: a login, or a link to the account logged in. */
export interface Continuation {
	/** At the start: its refusal, or what the transaction carries for the callback. */
	begin(
		request: HttpRequest,
		name: string,
	): Promise<{ answer: HttpResponse } | { carried: Carried }>;
	complete(at: Completing): Promise<HttpResponse>;
	/** A refusal after the take and before `complete`, recorded as this continuation records them. */
	failed(at: {
		readonly name: string;
		readonly reason: string;
		readonly transaction: Transaction;
		readonly source?: string;
		readonly userAgent?: string;
	}): void;
}

export interface Flow {
	readonly idps: ReadonlyMap<string, Idp>;
	readonly transactions: TransactionStore;
	readonly cookies: Cookies;
	/** The return targets a login may name. */
	readonly logins: Pick<Logins, "returnAllowed">;
	readonly login: Continuation;
	readonly link: Continuation;
	readonly random: Random;
	readonly clock: Clock;
	readonly log: Log;
	readonly landing: string;
	readonly transactionMs: number;
}

/** What a federation login proves. */
export const proves = ["fed"];

/** What a federation audit event says besides its kind and IdP, each only when known. */
export interface Recorded {
	readonly subject?: string | undefined;
	readonly reason?: string | undefined;
	readonly source?: string | undefined;
	readonly userAgent?: string | undefined;
}
/** Records the events under a prefix in federation's words: the IdP as `idp`, the address as `source`. */
export const recorderOf = (audit: Pick<Audit, "record">, prefix: string) => {
	const audited = declaredAudit(audit, events);
	return (outcome: string, name: string, at: Recorded) =>
		audited.record(`${prefix}.${outcome}` as keyof typeof events, {
			...(at.subject === undefined ? {} : { subject: at.subject }),
			attributes: {
				idp: name,
				...(at.source === undefined ? {} : { source: at.source }),
				...(at.userAgent === undefined ? {} : { userAgent: at.userAgent }),
				...(at.reason === undefined ? {} : { reason: at.reason }),
			},
		});
};

export const sent = (location: string, cookies: readonly string[]): HttpResponse => ({
	status: 302,
	headers: { ...noStore, location },
	cookies,
});
/** What a start or a callback answers when a store or the upstream cannot tell, in OAuth's word. */
const unavailable = { error: "temporarily_unavailable" };
const secret = (flow: Flow) => Buffer.from(flow.random.bytes(32)).toString("base64url");
export const secondOf = (ms: number) => Math.floor(ms / 1000) * 1000;
const s256 = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");
const cookieOf = (idp: string) => `federation.${idp}`;
/** A transaction's cookie; cross-site where the upstream posts its answer back from its own site. */
const writeCookie = (flow: Flow, name: string, idp: Idp, value: string, seconds: number) =>
	flow.cookies.write(cookieOf(name), value, seconds, idp.formPost ? { crossSite: true } : {});

/** The IdPs opened once, for the round trip and `upstreams`. */
export const federationIdps = contract<ReadonlyMap<string, Idp>>("federation.idps");

/** Where a login lands when it named no return target: the operator's landing, or the public origin's root. */
const landingWith = (landing: string | undefined, at: Pick<Site, "origin">) =>
	landing ?? `${at.origin}/`;

export const landingIn = async (c: BuildContext<Settings>) =>
	landingWith(c.section.landing, await c.get(site));

/** The round trip over the IdPs, ending in the continuation its start chose. */
export async function roundTripIn(
	c: BuildContext<Settings>,
	ends: Pick<Flow, "login" | "link">,
): Promise<(request: HttpRequest) => Promise<HttpResponse>> {
	const flow: Flow = {
		...ends,
		idps: await c.get(federationIdps),
		transactions: await c.get(transactionStore),
		cookies: await c.get(cookies),
		logins: await c.get(logins),
		random: c.random,
		clock: c.clock,
		log: c.log,
		landing: await landingIn(c),
		transactionMs: c.section["transaction-lifetime"] * 1000,
	};
	return (request) => federated(flow, request);
}

/** Answers a start or a callback under the federation path; anything else there is not found. */
export async function federated(flow: Flow, request: HttpRequest): Promise<HttpResponse> {
	const [name = "", step, ...rest] = request.path.slice(base.length + 1).split("/");
	const idp = flow.idps.get(name);
	if (!idp || rest.length > 0 || (step !== undefined && step !== "callback")) {
		return jsonAnswer(404, { error: "not_found" });
	}
	const method = step !== undefined && idp.formPost ? "POST" : "GET";
	if (request.method !== method) {
		const refused = jsonAnswer(405, { error: "method_not_allowed" });
		return { ...refused, headers: { ...refused.headers, allow: method } };
	}
	const params = method === "POST" ? request.form : request.query;
	if (params.repeated().length > 0) {
		return jsonAnswer(400, { error: "repeated_parameter" });
	}
	const at: At = { name, idp, request, params };
	try {
		return step === undefined ? await start(flow, at) : await callback(flow, at);
	} catch (error) {
		if (isUnavailable(error)) return jsonAnswer(503, unavailable);
		throw error;
	}
}

interface At {
	readonly name: string;
	readonly idp: Idp;
	readonly request: HttpRequest;
	readonly params: Values;
}

async function start(flow: Flow, { name, idp, request, params }: At) {
	const field = (key: string) => params.single(key);
	const target = field("redirect_to");
	if (target !== undefined && !flow.logins.returnAllowed(target)) {
		return jsonAnswer(400, { error: "invalid_redirect" });
	}
	const maxAge = field("max_age");
	if (maxAge !== undefined && !/^[0-9]{1,9}$/.test(maxAge)) {
		return jsonAnswer(400, { error: "invalid_request" });
	}
	// Only a start asking for it links; any other value is a login.
	const linking = ["1", "true"].includes(field("link") ?? "");
	const begun = await (linking ? flow.link : flow.login).begin(request, name);
	if ("answer" in begun) return begun.answer;
	// What the browser asks of the upstream's login, kept for the callback to judge it by.
	const asked = {
		...(field("prompt") === "login" ? { prompt: "login" as const } : {}),
		...(maxAge === undefined ? {} : { maxAgeSeconds: Number(maxAge) }),
	};
	const id = secret(flow);
	const transaction: Transaction = {
		...begun.carried,
		format: 1,
		idp: name,
		state: secret(flow),
		nonce: secret(flow),
		verifier: secret(flow),
		startedAt: flow.clock.now(),
		...(target === undefined ? {} : { redirectTo: target }),
		...asked,
	};
	// A record already under a fresh 256-bit id is a store that cannot keep it apart: unavailable.
	const saved = await flow.transactions.save(id, toStored(transaction), flow.transactionMs);
	if (saved !== "created") throw new Unavailable("federation");
	const location = idp.upstream.authorizationUrl({
		state: transaction.state,
		nonce: transaction.nonce,
		challenge: s256(transaction.verifier),
		challengeMethod: "S256",
		redirectUri: idp.redirectUri,
		...asked,
	});
	const seconds = Math.floor(flow.transactionMs / 1000);
	return sent(location, [writeCookie(flow, name, idp, id, seconds)]);
}

async function callback(flow: Flow, at: At) {
	const { name, idp, request, params } = at;
	const kept = flow.cookies.lookup(request, cookieOf(name));
	const id = kept.kind === "found" ? kept.value : undefined;
	const state = params.single("state");
	if (id === undefined || state === undefined) return jsonAnswer(400, { error: "invalid_state" });
	const transaction = await tookNow(flow, at, id, state);
	if (!transaction) return jsonAnswer(400, { error: "invalid_state" });
	// Spent from here on: its cookie goes with every answer. Before, a request from elsewhere
	// that did not carry its state must leave the browser's login in progress whole.
	const cleared = [writeCookie(flow, name, idp, "", 0)];
	try {
		return await finish(flow, at, transaction, cleared);
	} catch (error) {
		if (isUnavailable(error)) return jsonAnswer(503, unavailable, { cookies: cleared });
		throw error;
	}
}

async function tookNow(flow: Flow, { name }: At, id: string, state: string) {
	const taking = await flow.transactions.update(id, (stored) => {
		const current = fromStored(stored);
		if (!current || current.idp !== name || !sameSecret(current.state, state)) return undefined;
		return { value: toStored({ ...current, taken: true }) };
	});
	const before = fromStored(taking?.before);
	// Untaken before this change, and taken after it: this callback took it, and only once.
	if (!before || before.taken) return undefined;
	if (fromStored(taking?.after)?.taken !== true) return undefined;
	return before;
}

async function finish(flow: Flow, at: At, transaction: Transaction, cleared: readonly string[]) {
	const { name, idp, request, params } = at;
	const field = (key: string) => params.single(key);
	const from = determinedSource(request);
	const agent = request.headers.get("user-agent");
	const sender = {
		...(from === undefined ? {} : { source: from }),
		...(agent === undefined ? {} : { userAgent: agent }),
	};
	// A link's transaction never ends in a login, nor a login's in a link.
	const continuation = transaction.link ? flow.link : flow.login;
	// A round trip taken this far failed for the reason its answer names.
	const refused = (status: number, reason: string) => {
		continuation.failed({ name, reason, transaction, ...sender });
		return jsonAnswer(status, { error: reason }, { cookies: cleared });
	};
	const code = field("code");
	if (field("error") !== undefined || code === undefined) return refused(400, "upstream_refused");
	const upstreamLogin = await exchanged(flow, at, transaction, code);
	if (!upstreamLogin) return refused(502, "exchange_failed");
	if (!fresh(transaction, upstreamLogin, idp.upstream.clockSkewMs ?? 0, flow.clock.now())) {
		return refused(401, "login_required");
	}
	return continuation.complete({
		request,
		name,
		idp,
		upstreamLogin,
		transaction,
		...sender,
		cleared,
	});
}

async function exchanged(
	flow: Flow,
	{ name, idp, params }: At,
	transaction: Transaction,
	code: string,
) {
	try {
		return await idp.upstream.exchange({
			code,
			verifier: transaction.verifier,
			redirectUri: idp.redirectUri,
			nonce: transaction.nonce,
			iss: params.single("iss"),
		});
	} catch (error) {
		if (isUnavailable(error)) throw error;
		// Only the kind: an upstream's text and its tokens never reach logs or the browser.
		const kind = error instanceof UpstreamRefused ? "refused" : "failed";
		flow.log.warn("federation.exchange_failed", { idp: name, kind });
		return undefined;
	}
}

/** Whether the upstream login came after an ask to log in again, and within a max age; it must say when. */
function fresh(
	transaction: Transaction,
	upstreamLogin: UpstreamLogin,
	skewMs: number,
	now: number,
) {
	if (transaction.prompt === undefined && transaction.maxAgeSeconds === undefined) return true;
	const at = upstreamLogin.authenticatedAt;
	if (at === undefined) return false;
	if (transaction.prompt === "login" && at + skewMs < secondOf(transaction.startedAt)) return false;
	return (
		transaction.maxAgeSeconds === undefined || at + skewMs + transaction.maxAgeSeconds * 1000 >= now
	);
}
