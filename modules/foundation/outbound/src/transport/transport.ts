import { lookup as resolveName } from "node:dns/promises";
import { type ClientRequest, type IncomingMessage, request as plainRequest } from "node:http";
import { request as tlsRequest } from "node:https";
import { type Admitted, DestinationRefused, type Limits, type Policy } from "@mod/outbound-policy";
import type { OutboundRequest, OutboundResponse } from "../contract.ts";
import { type Tls, tlsOf } from "../tls/tls.ts";
import { failedAs, type PeerCheck, unavailable, wayOf, writtenAddress } from "./ways/ways.ts";

export type { PeerCheck } from "./ways/ways.ts";

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

/** Headers outbound always sends as its own: the product's name, and a body as sent. */
const ownHeaders = { "user-agent": "auth-provider", "accept-encoding": "identity" };

/** Headers outbound decides alone: its own, the host, and how the message is framed and carried. */
export const decided: ReadonlySet<string> = new Set([
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

/**
 * Resolves once and connects only to a checked address, or through the route's proxy; one deadline
 * covers it all, body included. Over TLS, `check` is waited on before the request goes.
 */
export async function send(
	admitted: Admitted,
	request: OutboundRequest,
	limits: Limits,
	resolve: Resolver,
	policy: Pick<Policy, "admitAddresses">,
	route: Route | undefined,
	tls: Tls,
	deadlineOf: (ms: number) => AbortSignal = AbortSignal.timeout,
	check?: PeerCheck,
	/** The kernel's monotonic time, which holds a checked connection to the deadline; none, its signal alone. */
	monotonic?: () => number,
	/** Plain http the proxy carries, but to direct hosts: outbound's own CRL fetch alone asks it. */
	plainThroughProxy = false,
): Promise<OutboundResponse> {
	const signal = deadlineOf(limits.timeoutMs);
	const until = monotonic && { monotonic, at: monotonic() + limits.timeoutMs };
	const way = await wayOf(admitted, resolve, policy, route, tls, signal, {
		...(check ? { check } : {}),
		...(until ? { until } : {}),
		plainThroughProxy,
	});
	const answer = await new Promise<IncomingMessage>((answered, failed) => {
		let outgoing: ClientRequest;
		try {
			const to = way.to;
			outgoing = (admitted.plain ? plainRequest : tlsRequest)({
				...(to
					? { host: to.host, port: to.port, lookup: to.lookup, path: to.path }
					: {
							hostname: writtenAddress(admitted) ?? admitted.host,
							port: admitted.port,
							path: `${admitted.url.pathname}${admitted.url.search}`,
						}),
				method: request.method ?? "GET",
				headers: {
					...callerHeaders(request.headers),
					...ownHeaders,
					...(to ? { host: admitted.url.host, ...to.headers } : {}),
				},
				...way.carry,
				...(admitted.plain ? {} : tlsOf(tls)),
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
