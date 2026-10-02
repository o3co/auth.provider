/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The outbound fetch's one HTTP exchange, over `node:https` / `node:http`:
 * the connection goes only to the addresses the policy checked (a `lookup`
 * that answers them and nothing else), the TLS server name and certificate
 * identity stay the URL's host, and each exchange has its own agent, so no
 * socket outlives it or is shared. Internal to core: the policy and the
 * answer's rules are `outbound-fetch.mts`'s.
 */

import { Agent as HttpAgent, request as httpRequest, type IncomingMessage } from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { isIP, type LookupFunction } from "node:net";

/** One exchange, as the policy admitted it. */
export interface OutboundExchange {
	readonly url: URL;
	/** The TLS server name: the host for a name, `undefined` for an IP literal. */
	readonly servername: string | undefined;
	/** The addresses the policy checked; the connection goes to one of these and nowhere else. */
	readonly addresses: readonly string[];
	readonly method: "GET" | "POST";
	readonly headers: Readonly<Record<string, string>>;
	readonly body: Uint8Array | undefined;
	/** Ends the exchange at any point: before the answer, or while its body is read. */
	readonly signal: AbortSignal;
}

/** The peer's answer, its body not yet read. */
export interface OutboundAnswer {
	readonly status: number;
	readonly statusText: string;
	readonly headers: readonly (readonly [string, string])[];
	/** The body as it arrives; read at most once. */
	readonly body: AsyncIterable<Uint8Array>;
	/** Releases the connection whether or not the body was read. Idempotent. */
	close(): void;
}

export type OutboundTransport = (exchange: OutboundExchange) => Promise<OutboundAnswer>;

/**
 * A `lookup` for `net.connect` that answers only `addresses`, in the shape
 * Node asks for: every address when asked for all, else the first of the
 * asked family (or the first).
 */
const pinnedLookup =
	(addresses: readonly string[]): LookupFunction =>
	(_hostname, options, callback) => {
		const entries = addresses.map((address) => ({ address, family: isIP(address) }));
		if (options.all === true) {
			(callback as (err: null, all: typeof entries) => void)(null, entries);
			return;
		}
		const family = typeof options.family === "number" ? options.family : 0;
		const chosen = entries.find((entry) => family === 0 || entry.family === family) ?? entries[0];
		if (chosen === undefined) {
			callback(Object.assign(new Error("no address"), { code: "ENOTFOUND" }), "", 0);
			return;
		}
		callback(null, chosen.address, chosen.family);
	};

/** The header pairs of `res`, in order, as the peer sent them. */
const headerPairs = (res: IncomingMessage): [string, string][] => {
	const pairs: [string, string][] = [];
	for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) {
		pairs.push([res.rawHeaders[i] ?? "", res.rawHeaders[i + 1] ?? ""]);
	}
	return pairs;
};

/**
 * The transport over Node's own HTTP stack. `tls.ca` replaces the trust
 * store, for tests that run a TLS peer with a certificate of their own.
 */
export function createNodeTransport(tls: { readonly ca?: string } = {}): OutboundTransport {
	return (exchange) =>
		new Promise<OutboundAnswer>((resolve, reject) => {
			if (exchange.signal.aborted) {
				reject(exchange.signal.reason);
				return;
			}
			const secure = exchange.url.protocol === "https:";
			const agent = secure
				? new HttpsAgent({ keepAlive: false, ...(tls.ca !== undefined ? { ca: tls.ca } : {}) })
				: new HttpAgent({ keepAlive: false });
			const hostname = exchange.url.hostname.startsWith("[")
				? exchange.url.hostname.slice(1, -1)
				: exchange.url.hostname;
			const req = (secure ? httpsRequest : httpRequest)({
				protocol: exchange.url.protocol,
				hostname,
				port: exchange.url.port === "" ? undefined : Number(exchange.url.port),
				path: `${exchange.url.pathname}${exchange.url.search}`,
				method: exchange.method,
				headers: {
					...exchange.headers,
					host: exchange.url.host,
				},
				agent,
				lookup: pinnedLookup(exchange.addresses),
				...(secure ? { servername: exchange.servername ?? "" } : {}),
			});
			let res: IncomingMessage | undefined;
			const close = () => {
				exchange.signal.removeEventListener("abort", onAbort);
				res?.destroy();
				req.destroy();
				agent.destroy();
			};
			const onAbort = () => {
				const reason = exchange.signal.reason;
				res?.destroy(reason instanceof Error ? reason : undefined);
				req.destroy(reason instanceof Error ? reason : undefined);
				agent.destroy();
				reject(reason);
			};
			req.on("error", (err) => {
				close();
				reject(err);
			});
			exchange.signal.addEventListener("abort", onAbort, { once: true });
			req.on("response", (incoming) => {
				res = incoming;
				// A body destroyed before it is read must not surface as an
				// uncaught error; a reader still sees the error through its iterator.
				incoming.on("error", () => undefined);
				resolve({
					status: incoming.statusCode ?? 0,
					statusText: incoming.statusMessage ?? "",
					headers: headerPairs(incoming),
					body: incoming,
					close,
				});
			});
			req.end(exchange.body === undefined ? undefined : Buffer.from(exchange.body));
		});
}

/** The transport the public factory uses. */
export const nodeTransport: OutboundTransport = createNodeTransport();
