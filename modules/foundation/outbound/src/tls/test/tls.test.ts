import { createServer as createPlainServer, type IncomingMessage, type Server } from "node:http";
import { createServer as createTlsServer } from "node:https";
import { type AddressInfo, connect, type Socket } from "node:net";
import { isUnavailable } from "@mod/kernel";
import { policyOf, policySettings } from "@mod/outbound-policy";
import { type Offer, peerOptions, testTlsOptions } from "@mod/tls-options/testing";
import { afterAll, afterEach, beforeAll, expect, it, vi } from "vitest";
// The contract first, as the package loads it: transport and credential import each other through it.
import "../../contract.ts";
import type { OutboundUnavailable } from "../../contract.ts";
import { type Route, send } from "../../transport.ts";
import { handshakeCodeOf, tlsOf } from "../tls.ts";

const anyPublic = policyOf(policySettings.parse({ "allow-any-public": true }));
const limits = { maxBytes: 1000, timeoutMs: 2000 };
const offers: readonly Offer[] = ["tls1.1", "static-rsa", "cbc", "ecdhe-aead", "tls1.3"];

/** Each peer, and the code of each handshake it refused: a refusal there, not another failure. */
const servers = new Map<Offer, { server: Server; port: number; ca: string; refused: string[] }>();
/** A proxy taking CONNECT to the port it is asked for on loopback. */
let proxy: Server;
let proxyPort = 0;

beforeAll(async () => {
	for (const offer of offers) {
		const { server: options, ca } = await peerOptions(offer);
		const server = createTlsServer(options, (_req, res) => res.end("{}"));
		await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
		const peer = {
			server,
			port: (server.address() as AddressInfo).port,
			ca,
			refused: [] as string[],
		};
		server.on("tlsClientError", (error: NodeJS.ErrnoException) => {
			peer.refused.push(error.code ?? error.message);
		});
		servers.set(offer, peer);
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

/** A request to the peer offering `offer`, directly or through the proxy's tunnel, trusting its authority unless told not. */
const reach = (offer: Offer, way: "direct" | "proxied", trusted = true) => {
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
	return send(admitted, {}, limits, async () => ["127.0.0.1"], anyPublic, route, {
		floor: testTlsOptions,
		...(trusted ? { ca } : {}),
	}).then(
		() => "answered",
		// The failure callers see, and the client's own TLS error code noted beside it.
		(error) =>
			isUnavailable(error)
				? `${(error as Partial<OutboundUnavailable>).failure}: ${handshakeCodeOf(error) ?? "no handshake refused"}`
				: error,
	);
};

it("holds every connection to tls-options' floor, directly and through a proxy [oidc-core-16.17-b] [oidc-core-16.17-c] [oidc-discovery-7.1-b] [oidc-discovery-7.1-c]", async () => {
	for (const way of ["direct", "proxied"] as const) {
		const outcomes = Object.fromEntries(
			await Promise.all(offers.map(async (offer) => [offer, await reach(offer, way)] as const)),
		);
		// Each refusal is the peer's handshake refused, never a connection failing otherwise.
		const refusals = Object.fromEntries(
			offers.map((offer) => [offer, servers.get(offer)?.refused]),
		);
		for (const peer of servers.values()) peer.refused = [];
		expect(refusals, way).toEqual({
			"tls1.1": ["ERR_SSL_UNSUPPORTED_PROTOCOL"],
			"static-rsa": ["ERR_SSL_NO_SHARED_CIPHER"],
			cbc: ["ERR_SSL_NO_SHARED_CIPHER"],
			"ecdhe-aead": [],
			"tls1.3": [],
		});
		// The client's side too, by the alert it got (RFC 8446 §6: 70 protocol_version, 40
		// handshake_failure): a reset or an early close after the peer's refusal notes none.
		expect(outcomes, way).toEqual({
			"tls1.1": "unreachable: TLS alert 70",
			"static-rsa": "unreachable: TLS alert 40",
			cbc: "unreachable: TLS alert 40",
			"ecdhe-aead": "answered",
			"tls1.3": "answered",
		});
	}
});

afterEach(() => vi.unstubAllEnvs());

it("checks the destination's certificate where NODE_TLS_REJECT_UNAUTHORIZED is 0, directly and through a proxy", async () => {
	vi.stubEnv("NODE_TLS_REJECT_UNAUTHORIZED", "0");
	for (const way of ["direct", "proxied"] as const) {
		expect(await reach("tls1.3", way, false), way).toMatch(/^unreachable: /);
		expect(await reach("tls1.3", way), way).toBe("answered");
	}
	for (const peer of servers.values()) peer.refused = [];
});

it("holds the test's authorities to the floor, and takes no copy of one", () => {
	expect(tlsOf({ floor: testTlsOptions, ca: "test authority" })).toEqual({
		ca: "test authority",
		minVersion: testTlsOptions.minVersion,
		ciphers: testTlsOptions.ciphers,
		rejectUnauthorized: true,
	});
	const loosened = { ...testTlsOptions, rejectUnauthorized: false, ca: "another" };
	expect(() => tlsOf({ floor: loosened, ca: "test authority" })).toThrow(TypeError);
});
