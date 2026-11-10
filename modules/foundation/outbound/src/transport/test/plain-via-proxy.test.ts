import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { policyOf, policySettings } from "@mod/outbound-policy";
import { testTlsOptions } from "@mod/tls-options/testing";
import { afterAll, beforeAll, expect, it } from "vitest";
// The package's contract first, as an app loads it: transport and credential import each other.
import "../../contract.ts";
import { type Route, send } from "../transport.ts";

const tls = { floor: testTlsOptions };
const policy = policyOf(policySettings.parse({ "allow-any-public": true }));
/** What the proxy was asked: the request line's target, the Host and its credentials. */
const asked: {
	url?: string | undefined;
	host?: string | undefined;
	authorization?: string | undefined;
}[] = [];
let answer: (res: ServerResponse) => void = (res) => res.end("crl");
let proxy: Server;
let port = 0;

beforeAll(async () => {
	proxy = createServer((req: IncomingMessage, res) => {
		asked.push({
			url: req.url,
			host: req.headers.host,
			authorization: req.headers["proxy-authorization"],
		});
		answer(res);
	});
	await new Promise<void>((done) => proxy.listen(0, "127.0.0.1", done));
	port = (proxy.address() as AddressInfo).port;
});
afterAll(() => proxy.close());

const route = (direct = false): Route => ({
	proxy: new URL(`http://proxy.example:${port}`),
	resolve: async () => ["127.0.0.1"],
	authorization: "Basic cHJveHk=",
	direct: () => direct,
});
const admitted = (url: string) => {
	const parsed = new URL(url);
	return {
		url: parsed,
		host: parsed.hostname,
		port: Number(parsed.port || 80),
		plain: true,
		loopback: false,
		internal: false,
	};
};
const fetching = (url: string, through = route(), limits = { maxBytes: 1000, timeoutMs: 2000 }) =>
	send(
		admitted(url),
		{},
		limits,
		async () => ["127.0.0.1"],
		policy,
		through,
		tls,
		AbortSignal.timeout,
		undefined,
		undefined,
		true,
	);
const failure = (sent: Promise<unknown>) =>
	sent.then(
		() => "answered",
		(error: { failure?: string; reason?: string }) => error.failure ?? error.reason,
	);

it("sends plain http the proxy carries as an absolute-form request, the destination its Host, the credentials the proxy's alone", async () => {
	asked.length = 0;
	const got = await fetching("http://crl.example/ca.crl?x=1");
	expect([got.status, new TextDecoder().decode(got.body)]).toEqual([200, "crl"]);
	expect(asked).toEqual([
		{ url: "http://crl.example/ca.crl?x=1", host: "crl.example", authorization: "Basic cHJveHk=" },
	]);
});

it("holds a request the proxy carries to the caller's caps: no redirect, its size, its deadline", async () => {
	answer = (res) => {
		res.writeHead(302, { location: "http://elsewhere.example/" });
		res.end();
	};
	expect(await failure(fetching("http://crl.example/ca.crl"))).toBe("redirect");
	answer = (res) => res.end("x".repeat(2000));
	expect(await failure(fetching("http://crl.example/ca.crl"))).toBe("too-large");
	answer = () => {};
	expect(
		await failure(
			fetching("http://crl.example/ca.crl", route(), { maxBytes: 1000, timeoutMs: 100 }),
		),
	).toBe("timeout");
	answer = (res) => res.end("crl");
});

it("checks an address the URL writes before the proxy is asked, and leaves a direct host and an unasked request to go direct", async () => {
	asked.length = 0;
	expect(await failure(fetching("http://10.0.0.1/ca.crl"))).toBe("special-address");
	// Direct: resolved and checked here, so the loopback answer is refused; the proxy is never asked.
	expect(await failure(fetching("http://crl.example/ca.crl", route(true)))).toBe("special-address");
	expect(
		await failure(
			send(
				admitted("http://crl.example/ca.crl"),
				{},
				{ maxBytes: 1000, timeoutMs: 2000 },
				async () => ["127.0.0.1"],
				policy,
				route(),
				tls,
			),
		),
	).toBe("special-address");
	expect(asked).toEqual([]);
});
