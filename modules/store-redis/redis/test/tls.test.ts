import type { AddressInfo, Socket } from "node:net";
import { createServer, getCACertificates, type Server, setDefaultCACertificates } from "node:tls";
import { assemble, type BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { heldToFloor, tlsOptions } from "@mod/tls-options";
import { type Offer, peerOptions, testTlsOptions } from "@mod/tls-options/testing";
import { Redis } from "ioredis";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import { clientDebugs, clientOptions, inTheClear } from "../src/client/client.ts";
import redisModule from "../src/module.ts";

const offers: readonly Offer[] = ["tls1.1", "static-rsa", "cbc", "ecdhe-aead", "tls1.3"];
const settings = (url: string) => ({
	url,
	prefix: "store",
	"connect-timeout": 2000,
	"replication-timeout": 1000,
	"command-timeout": 1000,
});

const servers: Server[] = [];
/** Every connection the peers took, agreed or not, so closing them waits on none. */
const held = new Set<Socket>();
afterAll(async () => {
	for (const socket of held) socket.destroy();
	await Promise.all(servers.map((s) => new Promise((done) => s.close(done))));
});

/** A peer offering `offer` alone, trusted, holding each connection it agrees to; what it refused. */
async function peer(offer: Offer) {
	const { server: options, ca } = await peerOptions(offer);
	setDefaultCACertificates([...getCACertificates("default"), ca]);
	const refused: string[] = [];
	const server = createServer(options, (socket) => socket.on("error", () => {}));
	server.on("connection", (socket: Socket) => held.add(socket));
	server.on("tlsClientError", (error: NodeJS.ErrnoException) => {
		refused.push(error.code ?? error.message);
	});
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	servers.push(server);
	return { port: (server.address() as AddressInfo).port, refused };
}

/** What the client's handshake came to: agreed, or the TLS alert that refused it. */
async function handshake(port: number): Promise<string> {
	const options = clientOptions(settings(`rediss://localhost:${port}`), testTlsOptions);
	const client = new Redis(`rediss://localhost:${port}`, { ...options, retryStrategy: () => null });
	// The client tells the handshake's own error by its error event; connecting fails as closed.
	const outcome = await new Promise<string>((done) => {
		client.once("connect", () => done("agreed"));
		client.once("error", (error: Error) => {
			done(/SSL alert number \d+/.exec(error.message)?.[0] ?? error.message);
		});
		client.connect().catch(() => {});
	});
	client.on("error", () => {});
	client.disconnect();
	return outcome;
}

it("passes the client the address family only when set", () => {
	expect(clientOptions(settings("redis://h:1"), testTlsOptions)).not.toHaveProperty("family");
	const of = (family: "ipv4" | "ipv6") =>
		clientOptions({ ...settings("redis://h:1"), "address-family": family }, testTlsOptions).family;
	expect([of("ipv4"), of("ipv6")]).toEqual([4, 6]);
});

it("passes the client no TLS over redis, and over rediss the floor's own keys alone", () => {
	expect(clientOptions(settings("redis://127.0.0.1:6379"), testTlsOptions)).not.toHaveProperty(
		"tls",
	);
	// The floor's own keys are tls-options' to name.
	expect(clientOptions(settings("rediss://127.0.0.1:6379"), testTlsOptions).tls).toEqual(
		heldToFloor(testTlsOptions, {}),
	);
	const loosened = { ...testTlsOptions, rejectUnauthorized: false };
	expect(() => clientOptions(settings("rediss://127.0.0.1:6379"), loosened)).toThrow(TypeError);
});

afterEach(() => vi.unstubAllEnvs());

// Before any peer below is trusted: the platform's store holds its authority only once `peer` adds it.
it("checks the server's certificate where NODE_TLS_REJECT_UNAUTHORIZED is 0, until its authority is trusted", async () => {
	vi.stubEnv("NODE_TLS_REJECT_UNAUTHORIZED", "0");
	const { server: options, ca } = await peerOptions("tls1.3");
	const server = createServer(options, (socket) => socket.on("error", () => {}));
	server.on("connection", (socket: Socket) => held.add(socket));
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	servers.push(server);
	const { port } = server.address() as AddressInfo;
	expect(await handshake(port)).toMatch(/self-signed certificate/);
	setDefaultCACertificates([...getCACertificates("default"), ca]);
	expect(await handshake(port)).toBe("agreed");
});

it("holds a rediss connection to tls-options' floor, the client passing its suites to the handshake [oidc-core-16.17-b]", async () => {
	const sides = [];
	for (const offer of offers) {
		const { port, refused } = await peer(offer);
		const outcome = await handshake(port);
		// The peer's side, by the handshake it refused, and the client's, by the alert it got.
		sides.push([offer, refused, outcome]);
	}
	// RFC 8446 §6: 70 protocol_version, 40 handshake_failure.
	expect(sides).toEqual([
		["tls1.1", ["ERR_SSL_UNSUPPORTED_PROTOCOL"], "SSL alert number 70"],
		["static-rsa", ["ERR_SSL_NO_SHARED_CIPHER"], "SSL alert number 40"],
		["cbc", ["ERR_SSL_NO_SHARED_CIPHER"], "SSL alert number 40"],
		["ecdhe-aead", [], "agreed"],
		["tls1.3", [], "agreed"],
	]);
});

it("refuses boot on a floor that is not tls-options' own, however alike, before connecting", async () => {
	const copied = { ...testTlsOptions };
	const another = defineModule({ name: "tls-options", replicaSafe: true, takes: [] }, (m) => [
		m.provide(tlsOptions).by(() => copied),
	]);
	const refused = await assemble({
		modules: [redisModule, another],
		config: { ...kernelConfig(), redis: { url: "rediss://localhost:1" } },
	}).catch((error: unknown) => error);
	expect((refused as BootRefused).refusals).toEqual([
		{
			where: "redis",
			reason: "the TLS floor is not one tls-options made: provide it from @mod/tls-options",
		},
	]);
});

it("finds any of the client's ioredis: logs turned on by DEBUG as the debug library reads it, and none where all are taken out or none named", () => {
	const on = [
		"ioredis:*",
		"ioredis:redis",
		"ioredis:connection",
		"*",
		"express:*,ioredis:*",
		"ioredis:*,-ioredis:connection",
		"*,-ioredis:connection",
		"*,-ioredis:redis",
		"*redis*",
		"io*",
		"*:redis",
		"*,-ioredis:r*",
		"ioredis:r*,-ioredis:r",
	];
	const off = [
		undefined,
		"",
		"express:*",
		"-ioredis:*",
		"*,-ioredis:*",
		"*,-*",
		"*,-io*",
		"ioredis:redis,-ioredis:redis",
		"ioredis.redis",
		"redis:*",
		"ioredis:",
	];
	expect(on.filter((debug) => !clientDebugs(debug))).toEqual([]);
	expect(off.filter((debug) => clientDebugs(debug))).toEqual([]);
});

it("finds a redis URL off this host in the clear, and neither rediss nor a loopback host by its name", () => {
	const clear = ["redis://redis.internal:6379", "redis://10.0.0.5", "redis://[2001:db8::1]:6379"];
	const not = [
		"rediss://redis.internal:6379",
		"redis://localhost:6379",
		"redis://127.0.0.1:6379",
		"redis://[::1]:6379",
		"redis://cache.localhost",
	];
	expect(clear.filter((url) => !inTheClear(url))).toEqual([]);
	expect(not.filter((url) => inTheClear(url))).toEqual([]);
});
