import { lookup as resolveName } from "node:dns/promises";
import {
	type ClientRequest,
	type IncomingMessage,
	Agent as PlainAgent,
	request as plainRequest,
} from "node:http";
import { Agent as TlsAgent, request as tlsRequest } from "node:https";
import type { LookupFunction, Socket } from "node:net";
import { isIP, connect as plainConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { type Admitted, DestinationRefused, type Limits, type Policy } from "@mod/outbound-policy";
import {
	isOutboundUnavailable,
	type OutboundFailure,
	type OutboundRequest,
	type OutboundResponse,
	OutboundUnavailable,
} from "./contract.ts";

const unbracketed = (host: string) => host.replace(/^\[(.*)\]$/, "$1");

/** Every address a name resolves to, once, waiting no longer than the request's deadline. */
export type Resolver = (name: string, signal: AbortSignal) => Promise<readonly string[]>;

/** A lookup of every address a name resolves to; IPv4 ones alone where `family` is 4. */
export type Lookup = (name: string, family?: 4) => Promise<readonly string[]>;

/** The system's lookup in this process: every address, in its order. */
export const systemLookup: Lookup = async (name, family) =>
	(await resolveName(name, { all: true, verbatim: true, ...(family ? { family } : {}) })).map(
		(found) => found.address,
	);

/** The proxy that carries requests, but to hosts it is told to leave direct; set by the operator, never read from the environment. */
export interface Route {
	readonly proxy: URL;
	/** How the proxy's own name is resolved: as the deployment's own lookups. */
	readonly resolve: Resolver;
	readonly authorization?: string;
	direct(host: string): boolean;
}

/** The authorities a destination's certificate is checked against, for a test; the platform's otherwise. */
export interface Trust {
	readonly ca?: string;
}

/** Headers outbound always sends as its own: the product's name, and a body as sent. */
const ownHeaders = { "user-agent": "auth-provider", "accept-encoding": "identity" };

/** Headers outbound decides alone: its own, the host, and how the message is framed and carried. */
const decided = new Set([
	...Object.keys(ownHeaders),
	"host",
	"content-length",
	"transfer-encoding",
	"connection",
	"keep-alive",
	"proxy-connection",
	"te",
	"trailer",
	"upgrade",
]);

/** The caller's headers, without those outbound decides, in any case. */
const callerHeaders = (headers: Readonly<Record<string, string>> = {}) =>
	Object.fromEntries(Object.entries(headers).filter(([name]) => !decided.has(name.toLowerCase())));

const unavailable = (failure: OutboundFailure) => new OutboundUnavailable(failure);

/** A failure of the connection, past the deadline or not; Node's error for headers past its cap. */
const failedAs = (error: unknown, signal: AbortSignal) => {
	if (isOutboundUnavailable(error)) return error;
	if (signal.aborted) return unavailable("timeout");
	const code = (error as { code?: unknown } | undefined)?.code;
	return unavailable(code === "HPE_HEADER_OVERFLOW" ? "too-large" : "unreachable");
};

/** The address the URL names, as written, never as the IPv4 address it may carry; none for a name. */
const writtenAddress = (admitted: Admitted) =>
	admitted.address ?? (isIP(admitted.host) !== 0 ? admitted.host : undefined);

async function addressesOf(admitted: Admitted, resolve: Resolver, signal: AbortSignal) {
	const written = writtenAddress(admitted);
	if (written !== undefined) return [written];
	// A deadline already past fires no more; the listener lives as long as this request's signal.
	if (signal.aborted) throw unavailable("timeout");
	const deadline = new Promise<never>((_, reject) =>
		signal.addEventListener("abort", () => reject(unavailable("timeout"))),
	);
	// Started inside the chain, so a resolver that throws at once is caught as well. The name is
	// resolved as the URL writes it, a trailing dot kept; the lists compare `host`.
	const resolved = Promise.resolve().then(() =>
		resolve(unbracketed(admitted.url.hostname), signal),
	);
	return Promise.race([resolved, deadline]).catch((error: unknown) => {
		throw failedAs(error, signal);
	});
}

async function bodyOf(answer: IncomingMessage, maxBytes: number, signal: AbortSignal) {
	const chunks: Buffer[] = [];
	let size = 0;
	try {
		for await (const chunk of answer as AsyncIterable<Buffer>) {
			size += chunk.length;
			if (size > maxBytes) throw unavailable("too-large");
			chunks.push(chunk);
		}
	} catch (error) {
		answer.destroy();
		throw failedAs(error, signal);
	}
	return new Uint8Array(Buffer.concat(chunks));
}

/** A tunnel to the destination through the proxy, by CONNECT; the proxy resolves the name and checks its addresses. */
async function tunnel(route: Route, admitted: Admitted, signal: AbortSignal) {
	// The name as the URL writes it, a trailing dot kept, as `addressesOf` resolves one: without its
	// dot, the proxy's resolver would apply its search domains.
	const named = writtenAddress(admitted) ?? unbracketed(admitted.url.hostname);
	const target = `${isIP(named) === 6 ? `[${named}]` : named}:${admitted.port}`;
	// The proxy's name is resolved as the deployment's own, never by this process's own lookup; every
	// address it answers is offered, so each family is tried in turn within the deadline, as before.
	const proxyHost = unbracketed(route.proxy.hostname);
	let addresses: readonly string[] = [proxyHost];
	if (isIP(proxyHost) === 0) {
		try {
			addresses = await route.resolve(proxyHost, signal);
		} catch (error) {
			throw failedAs(error, signal);
		}
	}
	const lookup: LookupFunction = (_name, options, answered) => {
		const found = addresses
			.filter((address) => !options.family || isIP(address) === options.family)
			.map((address) => ({ address, family: isIP(address) }));
		const [first] = found;
		if (first === undefined) {
			answered(Object.assign(new Error("no address"), { code: "ENOTFOUND" }), "", 0);
		} else if (options.all) answered(null, found);
		else answered(null, first.address, first.family);
	};
	return new Promise<Socket>((opened, failed) => {
		const asking = plainRequest({
			host: proxyHost,
			lookup,
			port: route.proxy.port || 80,
			method: "CONNECT",
			path: target,
			headers: {
				host: target,
				...(route.authorization ? { "proxy-authorization": route.authorization } : {}),
			},
			agent: false,
			signal,
		});
		asking.on("connect", (answer, socket) => {
			if (answer.statusCode === 200) return opened(socket);
			socket.destroy();
			failed(unavailable("proxy-refused"));
		});
		asking.on("error", (error) => failed(failedAs(error, signal)));
		asking.end();
	});
}

/** How a request reaches its destination, and what to let go if it is never made. */
interface Way {
	readonly carry: { readonly agent: PlainAgent };
	readonly release: () => void;
}

/** Through the proxy's tunnel, on a one-off agent whose TLS checks the destination's certificate; only an address in the URL is checked here, a name's are the proxy's. */
async function viaProxy(
	route: Route,
	admitted: Admitted,
	policy: Pick<Policy, "admitAddresses">,
	signal: AbortSignal,
	trust: Trust,
): Promise<Way> {
	const written = writtenAddress(admitted);
	const literal = written !== undefined;
	if (written !== undefined) policy.admitAddresses([written], admitted);
	const socket = await tunnel(route, admitted, signal);
	const agent = new TlsAgent({ keepAlive: false });
	agent.createConnection = () =>
		tlsConnect({
			socket,
			host: admitted.host,
			...(literal ? {} : { servername: admitted.host }),
			...trust,
		});
	return { carry: { agent }, release: () => socket.destroy() };
}

/** Directly, at the first of the checked addresses, on a one-off agent connecting there itself (a request's own lookup threw on a connect failing at once). */
async function atCheckedAddress(
	admitted: Admitted,
	resolve: Resolver,
	policy: Pick<Policy, "admitAddresses">,
	signal: AbortSignal,
	trust: Trust,
): Promise<Way> {
	const checked = policy.admitAddresses(await addressesOf(admitted, resolve, signal), admitted);
	const [address = ""] = checked;
	const at = { host: address, port: admitted.port };
	if (admitted.plain) {
		const agent = new PlainAgent({ keepAlive: false });
		agent.createConnection = () => plainConnect(at);
		return { carry: { agent }, release: () => {} };
	}
	const literal = isIP(admitted.host) !== 0;
	const agent = new TlsAgent({ keepAlive: false });
	agent.createConnection = () =>
		tlsConnect({ ...at, ...(literal ? {} : { servername: admitted.host }), ...trust });
	return { carry: { agent }, release: () => {} };
}

/** Resolves once and connects only to a checked address, or through the route's proxy; one deadline covers it all, body included. */
export async function send(
	admitted: Admitted,
	request: OutboundRequest,
	limits: Limits,
	resolve: Resolver,
	policy: Pick<Policy, "admitAddresses">,
	route?: Route,
	trust: Trust = {},
	deadlineOf: (ms: number) => AbortSignal = AbortSignal.timeout,
): Promise<OutboundResponse> {
	const signal = deadlineOf(limits.timeoutMs);
	const proxied = route !== undefined && !admitted.plain && !route.direct(admitted.host);
	const way = proxied
		? await viaProxy(route, admitted, policy, signal, trust)
		: await atCheckedAddress(admitted, resolve, policy, signal, trust);
	const answer = await new Promise<IncomingMessage>((answered, failed) => {
		let outgoing: ClientRequest;
		try {
			outgoing = (admitted.plain ? plainRequest : tlsRequest)({
				hostname: writtenAddress(admitted) ?? admitted.host,
				port: admitted.port,
				path: `${admitted.url.pathname}${admitted.url.search}`,
				method: request.method ?? "GET",
				headers: { ...callerHeaders(request.headers), ...ownHeaders },
				...way.carry,
				...(admitted.plain ? {} : trust),
				signal,
			});
		} catch (error) {
			// A request that cannot be made, such as for a header broken across lines, leaves no tunnel open.
			way.release();
			throw error;
		}
		outgoing.on("response", answered);
		outgoing.on("upgrade", (_answer, socket) => {
			socket.destroy();
			failed(unavailable("unsupported-answer"));
		});
		outgoing.on("error", (error) => failed(failedAs(error, signal)));
		// An abort is an error first, so a close alone is the connection lost.
		outgoing.on("close", () => failed(unavailable("unreachable")));
		outgoing.end(request.body);
	});
	const status = answer.statusCode ?? 0;
	if (status >= 300 && status < 400 && status !== 304) {
		answer.destroy();
		throw new DestinationRefused("redirect");
	}
	const encoding = answer.headers["content-encoding"];
	if (encoding !== undefined && encoding.toLowerCase() !== "identity") {
		answer.destroy();
		throw unavailable("unsupported-answer");
	}
	const body = await bodyOf(answer, limits.maxBytes, signal);
	const headers = new Map<string, string>();
	for (const [name, value] of Object.entries(answer.headers)) {
		if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(", ") : value);
	}
	return { status, headers, body };
}
