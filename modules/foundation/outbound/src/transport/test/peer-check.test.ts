import { createServer as createPlainServer, type Server } from "node:http";
import { createServer as createTlsServer } from "node:https";
import { type AddressInfo, connect, type Socket } from "node:net";
import type { TLSSocket } from "node:tls";
import { policyOf, policySettings } from "@mod/outbound-policy";
import { testTlsOptions } from "@mod/tls-options/testing";
import { afterAll, beforeAll, expect, it } from "vitest";
// The package's contract first, as an app loads it: transport and credential import each other.
import "../../contract.ts";
import { authority, destination } from "../../../test/fixtures/certificates.ts";
import { type Route, send } from "../transport.ts";

const anyPublic = policyOf(policySettings.parse({ "allow-any-public": true }));
const tls = { floor: testTlsOptions, ca: authority };
/** Whether the check had ended when the destination read each request. */
const readAfterCheck: boolean[] = [];
let checked = false;
let server: Server;
let proxy: Server;
let port = 0;
let proxyPort = 0;

beforeAll(async () => {
	server = createTlsServer(destination, (_req, res) => {
		readAfterCheck.push(checked);
		res.end("{}");
	});
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	port = (server.address() as AddressInfo).port;
	proxy = createPlainServer();
	proxy.on("connect", (_req, client: Socket) => {
		const upstream = connect(port, "127.0.0.1", () => {
			client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
			upstream.pipe(client).pipe(upstream);
		});
		for (const end of [client, upstream]) end.on("error", () => {});
	});
	await new Promise<void>((done) => proxy.listen(0, "127.0.0.1", done));
	proxyPort = (proxy.address() as AddressInfo).port;
});
afterAll(() => {
	server.close();
	proxy.close();
});

const admitted = () => ({
	url: new URL(`https://idp.example.test:${port}/`),
	host: "idp.example.test",
	port,
	plain: false,
	// Loopback lets 127.0.0.1 pass the address check, so the handshake reaches the server.
	loopback: true,
	internal: false,
});
const route = (): Route => ({
	proxy: new URL(`http://127.0.0.1:${proxyPort}`),
	resolve: async () => ["127.0.0.1"],
	direct: () => false,
});
const sending = (
	way: Route | undefined,
	timeoutMs: number,
	check: (s: TLSSocket, signal: AbortSignal) => Promise<void>,
) =>
	send(
		admitted(),
		{},
		{ maxBytes: 1000, timeoutMs },
		async () => ["127.0.0.1"],
		anyPublic,
		way,
		tls,
		AbortSignal.timeout,
		check,
	);

it("waits on the peer's check before any byte of the request goes, directly and through the proxy's tunnel", async () => {
	for (const way of [undefined, route()]) {
		checked = false;
		const peers: string[] = [];
		const answer = await sending(way, 2000, async (socket) => {
			peers.push(String(socket.getPeerCertificate().subject.CN));
			await new Promise((later) => setTimeout(later, 30));
			checked = true;
		});
		expect(answer.status).toBe(200);
		expect(peers).toEqual(["idp.example.test"]);
	}
	expect(readAfterCheck).toEqual([true, true]);
});

it("ends the connection at the deadline while the peer is checked, sending nothing", async () => {
	const read = readAfterCheck.length;
	for (const way of [undefined, route()]) {
		let held: TLSSocket | undefined;
		const failing = sending(way, 150, (socket, signal) => {
			held = socket;
			return new Promise((ended) => signal.addEventListener("abort", () => ended()));
		});
		await expect(failing).rejects.toMatchObject({ failure: "timeout" });
		expect(held?.destroyed).toBe(true);
	}
	expect(readAfterCheck.length).toBe(read);
});
