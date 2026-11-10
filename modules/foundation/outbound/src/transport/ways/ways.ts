import { Agent as PlainAgent, request as plainRequest } from "node:http";
import { Agent as TlsAgent } from "node:https";
import type { LookupFunction, Socket } from "node:net";
import { isIP, connect as plainConnect } from "node:net";
import { type TLSSocket, connect as tlsConnect } from "node:tls";
import type { Admitted, Policy } from "@mod/outbound-policy";
import {
	isOutboundUnavailable,
	type OutboundFailure,
	OutboundUnavailable,
} from "../../contract.ts";
import { noteHandshake, type Tls, tlsOf } from "../../tls/tls.ts";
import type { Resolver, Route } from "../transport.ts";

export const unbracketed = (host: string) => host.replace(/^\[(.*)\]$/, "$1");

export const unavailable = (failure: OutboundFailure) => new OutboundUnavailable(failure);

/** A failure of the connection, past the deadline or not; Node's error for headers past its cap. */
export const failedAs = (error: unknown, signal: AbortSignal) => {
	if (isOutboundUnavailable(error)) return error;
	if (signal.aborted) return unavailable("timeout");
	const code = (error as { code?: unknown } | undefined)?.code;
	return noteHandshake(
		unavailable(code === "HPE_HEADER_OVERFLOW" ? "too-large" : "unreachable"),
		error,
	);
};

/** The address the URL names, as written, never as the IPv4 address it may carry; none for a name. */
export const writtenAddress = (admitted: Admitted) =>
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

/**
 * How the proxy is reached: its name resolved as the deployment's own, never by this process's own
 * lookup; every address it answers is offered, so each family is tried in turn within the deadline.
 */
async function proxyReach(route: Route, signal: AbortSignal) {
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
	return { proxyHost, lookup };
}

/** A tunnel to the destination through the proxy, by CONNECT; the proxy resolves the name and checks its addresses. */
async function tunnel(route: Route, admitted: Admitted, signal: AbortSignal) {
	// The name as the URL writes it, a trailing dot kept, as `addressesOf` resolves one: without its
	// dot, the proxy's resolver would apply its search domains.
	const named = writtenAddress(admitted) ?? unbracketed(admitted.url.hostname);
	const target = `${isIP(named) === 6 ? `[${named}]` : named}:${admitted.port}`;
	const { proxyHost, lookup } = await proxyReach(route, signal);
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

/** A check of the peer a TLS connection reached, waited on before any byte of a request goes on it. */
export type PeerCheck = (socket: TLSSocket, signal: AbortSignal) => Promise<void>;

/** A request's deadline on the kernel's monotonic time: the time, and when the deadline falls. */
interface Until {
	readonly monotonic: () => number;
	readonly at: number;
}

/**
 * A TLS connection once its handshake is done and its peer checked, the deadline asked again after;
 * else it is ended, and the failure thrown is the connection's. A socket lost meanwhile ends it too.
 */
async function secured(socket: TLSSocket, signal: AbortSignal, check?: PeerCheck, until?: Until) {
	let lost: unknown;
	// Kept for the socket's life: an error while the peer is checked must not go unheard.
	socket.on("error", (error) => {
		lost ??= error;
	});
	let aborted = () => {};
	let closed = () => {};
	try {
		await new Promise<void>((done, failed) => {
			aborted = () => failed(unavailable("timeout"));
			closed = () => failed(lost ?? unavailable("unreachable"));
			signal.addEventListener("abort", aborted, { once: true });
			socket.once("close", closed);
			socket.once("secureConnect", () => done());
			if (signal.aborted) aborted();
		}).finally(() => {
			signal.removeEventListener("abort", aborted);
			socket.off("close", closed);
		});
		await check?.(socket, signal);
		// Timers held back by the check get their turn; the deadline is then asked by the monotonic
		// time, which a timer held back cannot pass.
		await new Promise((later) => setTimeout(later, 0));
		if (lost !== undefined || socket.destroyed) throw lost ?? unavailable("unreachable");
		if (signal.aborted || (until && until.monotonic() >= until.at)) throw unavailable("timeout");
		if (until) {
			// The request is asked again as it is first written: writing out its headers takes time too.
			const write = socket.write;
			socket.write = ((...args: Parameters<typeof write>) => {
				socket.write = write;
				if (until.monotonic() < until.at) return write.apply(socket, args);
				socket.destroy(unavailable("timeout"));
				return false;
			}) as typeof write;
		}
		return socket;
	} catch (error) {
		socket.destroy();
		throw failedAs(error, signal);
	}
}

/** How a request reaches its destination, and what to let go if it is never made. */
interface Way {
	readonly carry: { readonly agent: PlainAgent };
	/** Where the request itself goes, the proxy's for one it carries in absolute form; else the destination. */
	readonly to?: {
		readonly host: string;
		readonly port: number;
		readonly lookup: LookupFunction;
		readonly path: string;
		readonly headers: Readonly<Record<string, string>>;
	};
	readonly release: () => void;
}

/**
 * Plain http through the proxy, as an absolute-form request to it (signed material alone, which the
 * caller asks for): the proxy resolves the name and checks its addresses; only an address in the URL
 * is checked here. The proxy's credentials go to the proxy alone.
 */
async function plainViaProxy(
	route: Route,
	admitted: Admitted,
	policy: Pick<Policy, "admitAddresses">,
	signal: AbortSignal,
): Promise<Way> {
	const written = writtenAddress(admitted);
	if (written !== undefined) policy.admitAddresses([written], admitted);
	const { proxyHost, lookup } = await proxyReach(route, signal);
	return {
		carry: { agent: new PlainAgent({ keepAlive: false }) },
		to: {
			host: proxyHost,
			port: Number(route.proxy.port || 80),
			lookup,
			path: `${admitted.url.origin}${admitted.url.pathname}${admitted.url.search}`,
			headers: route.authorization ? { "proxy-authorization": route.authorization } : {},
		},
		release: () => {},
	};
}

/** Through the proxy's tunnel, on a one-off agent whose TLS checks the destination's certificate; only an address in the URL is checked here, a name's are the proxy's. */
async function viaProxy(
	route: Route,
	admitted: Admitted,
	policy: Pick<Policy, "admitAddresses">,
	signal: AbortSignal,
	tls: Tls,
	check?: PeerCheck,
	until?: Until,
): Promise<Way> {
	const written = writtenAddress(admitted);
	const literal = written !== undefined;
	if (written !== undefined) policy.admitAddresses([written], admitted);
	const tunnelled = await tunnel(route, admitted, signal);
	const socket = await secured(
		tlsConnect({
			socket: tunnelled,
			host: admitted.host,
			...(literal ? {} : { servername: admitted.host }),
			...tlsOf(tls),
		}),
		signal,
		check,
		until,
	);
	const agent = new TlsAgent({ keepAlive: false });
	agent.createConnection = () => socket;
	return { carry: { agent }, release: () => socket.destroy() };
}

/** Directly, at the first of the checked addresses, on a one-off agent connecting there itself (a request's own lookup threw on a connect failing at once). */
async function atCheckedAddress(
	admitted: Admitted,
	resolve: Resolver,
	policy: Pick<Policy, "admitAddresses">,
	signal: AbortSignal,
	tls: Tls,
	check?: PeerCheck,
	until?: Until,
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
	const socket = await secured(
		tlsConnect({ ...at, ...(literal ? {} : { servername: admitted.host }), ...tlsOf(tls) }),
		signal,
		check,
		until,
	);
	const agent = new TlsAgent({ keepAlive: false });
	agent.createConnection = () => socket;
	return { carry: { agent }, release: () => socket.destroy() };
}

/**
 * The way a request takes: directly, at an address checked here; through the proxy's tunnel over
 * TLS; or, for plain http the caller asks the proxy to carry, in absolute form to the proxy; but to
 * the route's direct hosts. Over TLS, the peer's check is waited on and the deadline held.
 */
export async function wayOf(
	admitted: Admitted,
	resolve: Resolver,
	policy: Pick<Policy, "admitAddresses">,
	route: Route | undefined,
	tls: Tls,
	signal: AbortSignal,
	how: { readonly check?: PeerCheck; readonly until?: Until; readonly plainThroughProxy: boolean },
): Promise<Way> {
	const proxied =
		route !== undefined &&
		(!admitted.plain || how.plainThroughProxy) &&
		!route.direct(admitted.host);
	if (!proxied)
		return atCheckedAddress(admitted, resolve, policy, signal, tls, how.check, how.until);
	if (admitted.plain) return plainViaProxy(route, admitted, policy, signal);
	return viaProxy(route, admitted, policy, signal, tls, how.check, how.until);
}
