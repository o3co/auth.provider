import { contract, extensionPoint, type Unavailable } from "@mod/kernel";
import type { Source } from "@mod/request-source";
import type { Values } from "./bodies/values.ts";

export type { Values } from "./bodies/values.ts";

export type Method = "GET" | "POST" | "PUT" | "DELETE";

export interface HttpRequest {
	readonly method: string;
	readonly path: string;
	readonly query: Values;
	/** An `application/x-www-form-urlencoded` body; empty for other bodies. */
	readonly form: Values;
	/** A JSON object body, frozen, for a route that takes JSON. */
	readonly json?: Readonly<Record<string, unknown>>;
	/** The body's values by name: a form's fields, or a JSON object's strings. */
	readonly fields: Values;
	/** The names of a JSON object's members that are not strings, so no field; none when there are none. */
	readonly mistyped?: ReadonlySet<string>;
	/** Lower-case names; repeated headers are joined with ", ". */
	readonly headers: ReadonlyMap<string, string>;
	readonly source: Source;
}

export type Body = string | Uint8Array | { readonly json: unknown };

/** What a page loads: its answer's policy allows these and nothing else. */
export interface Loads {
	/** The origins it frames, as `scheme://host[:port]`. */
	readonly frames?: readonly string[];
	/** The text of each inline script it runs. */
	readonly scripts?: readonly string[];
	/** Where its forms post: to this origin alone (`self`); none where it says nothing. */
	readonly forms?: "self";
}

export interface HttpResponse {
	readonly status: number;
	readonly headers?: Readonly<Record<string, string>>;
	/** `Set-Cookie` values, one header each. */
	readonly cookies?: readonly string[];
	readonly body?: Body;
	readonly loads?: Loads;
}

/** A rule a route can ask http to apply before its handler. Its owner makes it; it is unique as a value. */
export interface Policy<O = undefined> {
	readonly kind: "policy";
	readonly label: string;
	readonly __options?: O;
}

export function policy<O = undefined>(label: string): Policy<O> {
	return Object.freeze({ kind: "policy", label });
}

/** A route's use of a policy, with what the route gives it: plain data, copied and frozen at boot. */
export interface PolicyUse {
	readonly policy: Policy<unknown>;
	readonly options: unknown;
}

export function use<O>(policy: Policy<O>, ...options: O extends undefined ? [] : [O]): PolicyUse {
	return Object.freeze({ policy: policy as Policy<unknown>, options: options[0] });
}

/** How a policy applies: pass the request on to the next, or answer it. Throws Unavailable when it cannot tell. */
export interface PolicyRule {
	readonly policy: Policy<unknown>;
	apply(
		request: HttpRequest,
		options: unknown,
	): "pass" | HttpResponse | Promise<"pass" | HttpResponse>;
}

export function applying<O>(
	policy: Policy<O>,
	apply: (
		request: HttpRequest,
		options: O,
	) => "pass" | HttpResponse | Promise<"pass" | HttpResponse>,
): PolicyRule {
	return { policy: policy as Policy<unknown>, apply: apply as PolicyRule["apply"] };
}

/** The rules of the policies, one per policy; http matches them to policies by value. */
export const policies = extensionPoint<PolicyRule>("http.policies", { multiplicity: "many" });

/** What a route's policies keep: `own-site`, no other site's request reaches the handler; `per-source`, a source over its count does not. */
export type Guarantee = "own-site" | "per-source";

/** A policy owner's own claim that these policies keep a guarantee, each for the methods named; a claim, never a proof. */
export interface Mark {
	readonly guarantee: Guarantee;
	readonly policies: readonly {
		readonly policy: Policy<unknown>;
		readonly methods: readonly Method[];
	}[];
}

/** One mark per guarantee, matched to the policies a route uses by value. */
export const marks = extensionPoint<Mark>("http.marks", {
	multiplicity: "keyed",
	keyOf: (mark) => mark.guarantee,
});

/** A form is `application/x-www-form-urlencoded`; JSON is `application/json`; none is no body at all. */
export type BodyKind = "form" | "json" | "none";

/** A route that takes cross-origin requests from the origins the operator lists; never with credentials. */
export interface CorsRule {
	/** Request headers a page may send beyond the safelisted ones, lower case. */
	readonly headers?: readonly string[];
	/** Response headers a page may read beyond the safelisted ones, lower case. */
	readonly exposes?: readonly string[];
}

export interface Route {
	readonly method: Method;
	readonly path: string;
	/** Applied in this order before `handle`; the first that answers ends the request. */
	readonly uses?: readonly PolicyUse[];
	/** The bodies the route takes, by type; any other is `415`. Without it, only a form is read. */
	readonly takes?: readonly BodyKind[];
	/** Takes cross-origin requests; without it, none is answered as one. */
	readonly cors?: CorsRule;
	/** Whether it changes what the server keeps or the access a cookie gives; a GET says, any other method does. */
	readonly changesState?: boolean;
	/** Why a route changing state uses no policy marked `own-site` for its method. */
	readonly crossSite?: string;
	/** Why a route changing state uses no policy marked `per-source` for its method. */
	readonly unlimited?: string;
	/** The answer when a policy or the handler throws Unavailable; without it, http's own. */
	readonly unavailable?: UnavailableAnswer;
	handle(request: HttpRequest): HttpResponse | Promise<HttpResponse>;
}

/** A route's answer to Unavailable, given after http's one warning of it. */
export interface UnavailableAnswer {
	readonly response: HttpResponse;
	/** What only the route knows: fields for http's warning, and anything it records itself (an audit event). */
	noted?(
		request: HttpRequest,
		unavailable: Unavailable,
	): Readonly<Record<string, string>> | undefined;
}

export interface Listening {
	port(): number;
}

export const routes = extensionPoint<Route>("http.routes", {
	multiplicity: "keyed",
	keyOf: (route) => `${route.method} ${route.path}`,
});

export const listening = contract<Listening>("http.listening");

/** Where browsers reach this deployment. */
export interface Site {
	/** Undefined when the operator did not state it. */
	readonly origin: string | undefined;
	/** Whether cookies can be made secure (`__Host-` and Secure): false only for a plain-http origin. */
	readonly secureCookies: boolean;
	/** Whether it is reached through a proxy it trusts (`trusted-proxies` names one): only then can a request's scheme be https or its source be told past the proxy. */
	readonly proxied: boolean;
}

export const site = contract<Site>("http.site");

/** A request's end, once per request, when it was answered or its connection closed. */
export interface RequestEnd {
	/** The method as sent. */
	readonly method: string;
	/** The declared path of the route the request reached; none when it reached none. */
	readonly route?: string;
	/** The status written, or `closed` when the client closed before any answer was written. */
	readonly status: number | "closed";
	/** Milliseconds from the request's arrival to its end; never negative. */
	readonly ms: number;
}

/** Hears each request's end, after the request and asynchronously; what it throws or rejects is dropped, never reaching the request or the others. */
export interface RequestEndObserver {
	ended(end: RequestEnd): void;
}

export const requestEnds = extensionPoint<RequestEndObserver>("http.request-ends", {
	multiplicity: "many",
});

/** Headers keeping an answer out of every cache, HTTP/1.0 ones included (RFC 6749 §5.1). */
export const noStore = Object.freeze({ "cache-control": "no-store", pragma: "no-cache" });

/** A JSON answer kept out of caches, with any cookies and headers it adds; a header given replaces `noStore`'s of its name. */
export const jsonAnswer = (
	status: number,
	json: unknown,
	extra: { readonly cookies?: readonly string[]; readonly headers?: Record<string, string> } = {},
): HttpResponse => ({
	status,
	headers: { ...noStore, ...extra.headers },
	body: { json },
	...(extra.cookies?.length ? { cookies: extra.cookies } : {}),
});
