import {
	createServer,
	type IncomingMessage,
	type Server,
	type ServerResponse,
	validateHeaderName,
	validateHeaderValue,
} from "node:http";
import type { Socket } from "node:net";
import { ignoredCertificates } from "@mod/client-certificate";
import { type Clock, isUnavailable, type Log, type Unavailable } from "@mod/kernel";
import { ignoredForwarding, sourceOf, type TrustedProxies } from "@mod/request-source";
import { bodyOf } from "../bodies/body.ts";
import { paramsOf, readOnly } from "../bodies/values.ts";
import {
	type HttpRequest,
	type HttpResponse,
	jsonAnswer,
	noStore,
	type RequestEndObserver,
} from "../contract.ts";
import { crossOrigin, preflight } from "../cors/cors.ts";
import { ending } from "../ending/ending.ts";
import type { GuardedRoute } from "../guards/guards.ts";
import { secured } from "../security-headers/security-headers.ts";
import { firstReaching } from "./paths.ts";

/** The request as far as its route is known; the body is read as the route says. */
type Head = Omit<HttpRequest, "form" | "json" | "fields">;

/** What the server answers with. */
export interface Serving {
	readonly routes: readonly GuardedRoute[];
	readonly proxies: TrustedProxies;
	readonly origins: ReadonlySet<string>;
	readonly ends: readonly RequestEndObserver[];
	readonly log: Log;
	readonly clock: Clock;
	/** How long a request's headers, and the whole request, may take to arrive; and the connections held at once. */
	readonly limits: {
		readonly headersMs: number;
		readonly requestMs: number;
		readonly connections: number;
	};
}

/** The request's head; undefined when the request target is not a URL, or its query not UTF-8. */
function frozenHead(message: IncomingMessage, proxies: TrustedProxies): Head | undefined {
	const url = URL.parse(message.url ?? "/", "http://placeholder");
	const query = url && paramsOf(url.search.slice(1));
	if (!url || !query) return undefined;
	const headers = new Map<string, string>();
	for (const [key, value] of Object.entries(message.headers)) {
		if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
	}
	return Object.freeze({
		method: message.method ?? "GET",
		path: url.pathname,
		query,
		headers: readOnly(headers),
		source: sourceOf(proxies, message.socket.remoteAddress ?? "", headers),
	});
}

/** A JSON answer holding members whose value is null: their key paths, never their values. */
class NullMembers extends Error {
	readonly paths: readonly string[];
	constructor(paths: readonly string[]) {
		super("null members");
		this.paths = paths;
	}
}

/** The key paths of the members whose value is null, in objects at any depth, arrays' among them. */
function nullMembers(value: unknown, at = "", found: string[] = []): string[] {
	if (Array.isArray(value)) {
		for (const [i, item] of value.entries()) nullMembers(item, `${at}[${i}]`, found);
	} else if (typeof value === "object" && value !== null) {
		for (const [key, member] of Object.entries(value)) {
			const path = at ? `${at}.${key}` : key;
			if (member === null) found.push(path);
			else nullMembers(member, path, found);
		}
	}
	return found;
}

/** Writes the answer; one whose headers cannot be written becomes a bare 500, as does any failure. */
function write(res: ServerResponse, response: HttpResponse, log: Log): void {
	try {
		const { headers, payload } = serialized(response);
		for (const [name, value] of Object.entries(headers)) {
			validateHeaderName(name);
			for (const v of [value].flat()) validateHeaderValue(name, v);
		}
		res.writeHead(response.status, headers);
		res.end(payload);
	} catch (error) {
		if (error instanceof NullMembers) {
			// The provider writes no member as null (OpenID Connect Core §13.3): a member it has no value for is left out.
			log.error("http.failed", { kind: "null_member", members: error.paths.join(" ") });
		} else
			log.error("http.unwritable", { kind: error instanceof Error ? error.name : typeof error });
		if (!res.headersSent) res.writeHead(500, secured(noStore));
		res.end();
	}
}

/** The answer as written: its header fields, security headers, cookies and length included, and its payload. */
function serialized(response: HttpResponse) {
	const headers: Record<string, string | string[]> = secured(
		response.headers ?? {},
		response.loads,
	);
	if (response.cookies?.length) headers["set-cookie"] = [...response.cookies];
	const body = response.body;
	const isJson = typeof body === "object" && "json" in body;
	if (isJson) {
		const nulls = nullMembers(body.json);
		if (nulls.length > 0) throw new NullMembers(nulls);
		headers["content-type"] ??= "application/json";
	}
	const payload = isJson ? JSON.stringify(body.json) : body;
	// Stated, not chunked, so a HEAD answer carries the length its GET would.
	if (payload !== undefined) headers["content-length"] = String(Buffer.byteLength(payload));
	return { headers, payload };
}

const bare = (status: number): HttpResponse => ({ status, headers: noStore });

/** The routes a path reaches: those of the declared path that comes first for it. */
function reaching(routes: readonly GuardedRoute[], path: string): readonly GuardedRoute[] {
	const first = firstReaching(
		routes.map((r) => r.path),
		path,
	);
	return routes.filter((r) => first.has(r.path));
}

/** A GET that changes state is never reached by HEAD, which must change nothing. */
const answersHead = (r: GuardedRoute) => r.method === "GET" && r.changesState !== true;

function routeFor(reached: readonly GuardedRoute[], method: string): GuardedRoute | undefined {
	const route = reached.find((r) => r.method === method);
	return route ?? (method === "HEAD" ? reached.find(answersHead) : undefined);
}

async function answer(
	serving: Serving,
	head: Head,
	message: IncomingMessage,
	nameRoute: (path: string) => void,
): Promise<HttpResponse> {
	const reaches = reaching(serving.routes, head.path);
	const origin = head.headers.get("origin");
	const asked = head.headers.get("access-control-request-method");
	if (head.method === "OPTIONS" && asked !== undefined) {
		const answered = preflight(reaches, asked, origin, serving.origins);
		if (answered) return answered;
	}
	const route = routeFor(reaches, head.method);
	if (!route) {
		if (reaches.length === 0) return bare(404);
		const allowed = reaches.flatMap((r) => (answersHead(r) ? ["GET", "HEAD"] : [r.method]));
		return { status: 405, headers: { ...noStore, allow: allowed.join(", ") } };
	}
	nameRoute(route.path);
	const response = await handled(route, head, message, serving.log);
	return route.cors ? crossOrigin(route.cors, origin, serving.origins, response) : response;
}

async function handled(
	route: GuardedRoute,
	head: Head,
	message: IncomingMessage,
	log: Log,
): Promise<HttpResponse> {
	const { refused, ...body } = await bodyOf(route.takes, message);
	const request: HttpRequest = Object.freeze({ ...head, ...body });
	try {
		const guarded = (await route.guard?.(request)) ?? "pass";
		if (guarded !== "pass") return guarded;
		if (refused) return bare(refused);
		return await route.handle(request);
	} catch (error) {
		if (isUnavailable(error)) return unavailable(route, request, error, log);
		failed(error, log);
		return bare(500);
	}
}

/** A policy's or handler's failure, by its kind only. */
function failed(error: unknown, log: Log): void {
	log.error("http.failed", { kind: error instanceof Error ? error.name : typeof error });
}

/** The route's answer to Unavailable, or http's own, after one warning with what the route notes. */
function unavailable(
	route: GuardedRoute,
	request: HttpRequest,
	error: Unavailable,
	log: Log,
): HttpResponse {
	let noted: Readonly<Record<string, string>> | undefined;
	try {
		noted = route.unavailable?.noted?.(request, error);
	} catch (failure) {
		failed(failure, log);
	}
	log.warn("http.unavailable", { ...noted, what: error.what, route: route.path });
	return route.unavailable?.response ?? jsonAnswer(503, { error: "service_unavailable" });
}

/** Warns of the forwarded headers a request's peer sent and were ignored, in http's words. */
function ignoredHeaders({ proxies, log, clock }: Serving) {
	const forwarding = ignoredForwarding(proxies, clock);
	const certificates = ignoredCertificates(proxies.certificate, clock);
	return (head: Head, peer: string) => {
		const fields = { peer: head.source.address };
		if (forwarding(peer, head.headers)) log.warn("http.forwarded_from_untrusted_peer", fields);
		if (certificates(head.headers, head.source.clientCertificate)) {
			log.warn("http.client_certificate_ignored", fields);
		}
	};
}

export function serve(serving: Serving): Server {
	const { proxies, log, clock } = serving;
	const warn = ignoredHeaders(serving);
	/** Each connection's requests in flight; one with none is ended once stop begins, after what it still has to send. */
	const inFlight = new Map<Socket, number>();
	const open = new Set<Socket>();
	const endIfDone = (socket: Socket) => {
		if (!server.listening && !inFlight.has(socket)) socket.end();
	};
	const { headersMs, requestMs, connections } = serving.limits;
	// Node checks the two times every 30 seconds by default; this checks often enough to keep them.
	const checking = { connectionsCheckingInterval: Math.min(1000, headersMs) };
	const timeouts = { headersTimeout: headersMs, requestTimeout: requestMs, ...checking };
	const server = createServer(timeouts, (req, res) => {
		// Outside the chain, so it must never throw: it reads the clock and adds listeners; observers
		// are told later. Every other step runs inside, so a throw there is answered.
		const told = ending(serving.ends, clock, req, res);
		const socket = req.socket;
		inFlight.set(socket, (inFlight.get(socket) ?? 0) + 1);
		res.once("close", () => {
			const left = (inFlight.get(socket) ?? 1) - 1;
			if (left > 0) inFlight.set(socket, left);
			else inFlight.delete(socket);
			endIfDone(socket);
		});
		let route: string | undefined;
		const nameRoute = (path: string) => {
			route = path;
			told(path);
		};
		const reply = (response: HttpResponse) => {
			const stopping = !server.listening;
			if (stopping) res.setHeader("connection", "close");
			write(res, response, log);
		};
		void Promise.resolve()
			.then(() => {
				const head = frozenHead(req, proxies);
				if (head === undefined) return bare(400);
				warn(head, req.socket.remoteAddress ?? "");
				return answer(serving, head, req, nameRoute);
			})
			.then(reply)
			.catch((error: unknown) => {
				const kind = error instanceof Error ? error.name : typeof error;
				log.warn("http.unexpected_failure", { ...(route && { route }), kind });
				reply(bare(500));
			});
	});
	server.maxConnections = connections;
	server.on("connection", (socket: Socket) => {
		open.add(socket);
		socket.once("close", () => {
			open.delete(socket);
			inFlight.delete(socket);
		});
	});
	// Node's own, which close() calls before the server stops listening, destroys an idle connection at
	// once, cutting an answer still being sent.
	server.closeIdleConnections = () => {
		for (const socket of open) if (!inFlight.has(socket)) socket.end();
	};
	return server;
}

/** Accepts nothing new and lets requests in flight finish; once `signal` aborts, closes the rest. */
export function drain(server: Server, signal: AbortSignal): Promise<void> {
	const closed = new Promise<void>((resolve) => server.close(() => resolve()));
	const cut = () => server.closeAllConnections();
	if (signal.aborted) cut();
	else signal.addEventListener("abort", cut, { once: true });
	return closed;
}
