import { createServer as createPlainServer, type IncomingMessage, type Server } from "node:http";
import { createServer as createTlsServer } from "node:https";
import { type AddressInfo, connect, type Socket } from "node:net";
import { isUnavailable } from "@mod/kernel";
import { policyOf, policySettings } from "@mod/outbound-policy";
import { type Offer, peerOptions } from "@mod/tls-options/testing";
import { afterAll, beforeAll, expect, it } from "vitest";
// The contract first, as the package loads it: transport and credential import each other through it.
import "../src/contract.ts";
import type { OutboundUnavailable } from "../src/contract.ts";
import { type Route, send } from "../src/transport.ts";

const anyPublic = policyOf(policySettings.parse({ "allow-any-public": true }));
const limits = { maxBytes: 1000, timeoutMs: 2000 };
const offers: readonly Offer[] = ["tls1.1", "static-rsa", "cbc", "ecdhe-aead", "tls1.3"];

const servers = new Map<Offer, { server: Server; port: number; ca: string }>();
/** A proxy taking CONNECT to the port it is asked for on loopback. */
let proxy: Server;
let proxyPort = 0;

beforeAll(async () => {
	for (const offer of offers) {
		const { server: options, ca } = await peerOptions(offer);
		const server = createTlsServer(options, (_req, res) => res.end("{}"));
		await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
		servers.set(offer, { server, port: (server.address() as AddressInfo).port, ca });
	}
	proxy = createPlainServer();
	proxy.on("connect", (req: IncomingMessage, client: Socket) => {
		const port = Number(new URL(`http://${req.url}`).port);
		const upstream = connect(port, "127.0.0.1", () => {
			client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
			upstream.pipe(client);
			client.pipe(upstream);
		});
		upstream.on("error", () => client.destroy());
		client.on("error", () => upstream.destroy());
	});
	await new Promise<void>((done) => proxy.listen(0, "127.0.0.1", done));
	proxyPort = (proxy.address() as AddressInfo).port;
});

afterAll(() => {
	for (const { server } of servers.values()) server.close();
	proxy.close();
});

/** A request to the peer offering `offer`, directly or through the proxy's tunnel. */
const reach = (offer: Offer, way: "direct" | "proxied") => {
	const { port = 0, ca = "" } = servers.get(offer) ?? {};
	const admitted = {
		url: new URL(`https://localhost:${port}/`),
		host: "localhost",
		port,
		plain: false,
		loopback: true,
		internal: false,
	};
	const route: Route | undefined =
		way === "proxied"
			? {
					proxy: new URL(`http://127.0.0.1:${proxyPort}`),
					resolve: async () => ["127.0.0.1"],
					direct: () => false,
				}
			: undefined;
	return send(admitted, {}, limits, async () => ["127.0.0.1"], anyPublic, route, { ca }).then(
		() => "answered",
		(error) => (isUnavailable(error) ? (error as Partial<OutboundUnavailable>).failure : error),
	);
};

it("holds every connection to tls-options' floor, directly and through a proxy [oidc-core-16.17-b] [oidc-core-16.17-c] [oidc-discovery-7.1-b] [oidc-discovery-7.1-c]", async () => {
	for (const way of ["direct", "proxied"] as const) {
		const outcomes = Object.fromEntries(
			await Promise.all(offers.map(async (offer) => [offer, await reach(offer, way)] as const)),
		);
		expect(outcomes, way).toEqual({
			"tls1.1": "unreachable",
			"static-rsa": "unreachable",
			cbc: "unreachable",
			"ecdhe-aead": "answered",
			"tls1.3": "answered",
		});
	}
});
