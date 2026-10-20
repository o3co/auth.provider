import { createServer as createPlainServer, type IncomingMessage, type Server } from "node:http";
import { createServer as createTlsServer } from "node:https";
import { type AddressInfo, connect, type Socket } from "node:net";
import { isUnavailable } from "@mod/kernel";
import { configuredUrl } from "@mod/url-setting/testing";
import { afterAll, beforeAll, beforeEach, expect, it } from "vitest";
import type { OutboundUnavailable } from "../src/contract.ts";
import { outboundOver, section } from "../src/module.ts";
import {
	addressAuthority,
	atProxyAddress,
	atPublicAddress,
	authority,
	destination,
} from "./fixtures/certificates.ts";

/** An upstream IdP at idp.example.test, reached only through the proxy. */
let idp: Server;
let idpPort = 0;
/** A proxy taking CONNECT, tunnelling every target to the IdP; it records what it was asked. */
let proxy: Server;
let proxyPort = 0;
const asked: { target: string; authorization: string | undefined }[] = [];
/** The proxy's side of each tunnel it opened. */
const tunnels: Socket[] = [];
/** How the proxy answers CONNECT: open the tunnel, refuse it, or never answer. */
let answering: "tunnel" | "refuse" | "stall" = "tunnel";
/** Where the proxy's tunnels lead: the IdP unless a test names another server. */
let upstreamPort = 0;
/** Servers presenting a certificate for one address alone. */
const byAddress: Record<"proxy" | "public", { server: Server; port: number }> = {} as never;

/** A port no test takes: `listen(0)` picks from the ephemeral range, never port 1. */
const refusedPort = 1;

beforeAll(async () => {
	const answer = await new Promise<string>((resolve) => {
		const socket = connect(refusedPort, "127.0.0.1");
		socket.once("connect", () => {
			socket.destroy();
			resolve("connected");
		});
		socket.once("error", (error: NodeJS.ErrnoException) => resolve(error.code ?? "error"));
	});
	if (answer !== "ECONNREFUSED") {
		throw new Error(
			`127.0.0.1:${refusedPort} must refuse connections for these tests (got ${answer})`,
		);
	}
});

beforeAll(async () => {
	idp = createTlsServer(destination, (req: IncomingMessage, res) => {
		const routes: Record<string, string> = {
			"/.well-known/openid-configuration": '{"issuer":"https://idp.example.test"}',
			"/jwks": '{"keys":[]}',
			"/token": '{"access_token":"at"}',
		};
		res.setHeader("content-type", "application/json");
		res.end(routes[req.url ?? ""] ?? "{}");
	});
	await new Promise<void>((done) => idp.listen(0, "127.0.0.1", done));
	idpPort = (idp.address() as AddressInfo).port;
	proxy = createPlainServer();
	proxy.on("connect", (req: IncomingMessage, client: Socket) => {
		asked.push({ target: req.url ?? "", authorization: req.headers["proxy-authorization"] });
		tunnels.push(client);
		if (answering === "stall") return;
		if (answering === "refuse") {
			client.end("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
			return;
		}
		const upstream = connect(upstreamPort || idpPort, "127.0.0.1", () => {
			client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
			upstream.pipe(client);
			client.pipe(upstream);
		});
		upstream.on("error", () => client.destroy());
	});
	await new Promise<void>((done) => proxy.listen(0, "127.0.0.1", done));
	proxyPort = (proxy.address() as AddressInfo).port;
	for (const [name, certificate] of [
		["proxy", atProxyAddress],
		["public", atPublicAddress],
	] as const) {
		const server = createTlsServer(certificate, (_req, res) => res.end("{}"));
		await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
		byAddress[name] = { server, port: (server.address() as AddressInfo).port };
	}
});

beforeEach(() => {
	asked.length = 0;
	resolved.length = 0;
	answering = "tunnel";
	upstreamPort = 0;
});

afterAll(() => {
	idp.close();
	proxy.close();
	for (const { server } of Object.values(byAddress)) server.close();
});

/** Names are never resolved here when the proxy carries a request: the proxy resolves them. */
const resolved: string[] = [];
const noResolving = async (host: string): Promise<readonly string[]> => {
	resolved.push(host);
	return ["127.0.0.1"];
};
const paths = (settings: Record<string, unknown>) =>
	outboundOver(section.parse({ allow: ["idp.example.test"], ...settings }), noResolving, {
		ca: authority,
	});
const viaProxy = () =>
	paths({ proxy: `http://127.0.0.1:${proxyPort}`, "proxy-authorization": "Basic dGVzdA==" });
const at = (path: string) => `https://idp.example.test:${idpPort}${path}`;
const text = (body: Uint8Array) => new TextDecoder().decode(body);

it("reaches an IdP's discovery, key set and token endpoint through the proxy, as 0.17 did with HTTPS_PROXY", async () => {
	const out = viaProxy();
	const discovered = await out.fetch(at("/.well-known/openid-configuration"));
	const keys = await out.fetchSigned(at("/jwks"), {}, { hosts: ["idp.example.test"] });
	const token = await out.fetch(at("/token"), {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new TextEncoder().encode("grant_type=authorization_code"),
	});
	expect([discovered.status, keys.status, token.status]).toEqual([200, 200, 200]);
	expect(text(token.body)).toBe('{"access_token":"at"}');
	// Each went by CONNECT to the destination's name, with the proxy's credentials; nothing was resolved here.
	expect(asked).toEqual(
		Array(3).fill({ target: `idp.example.test:${idpPort}`, authorization: "Basic dGVzdA==" }),
	);
	expect(resolved).toEqual([]);
});

it("connects directly to a host listed as direct, resolving it as without a proxy", async () => {
	const direct = paths({
		proxy: `http://127.0.0.1:${proxyPort}`,
		"direct-hosts": ["idp.example.test"],
		"plain-loopback": [],
	});
	// The name resolves to the loopback, which the policy keeps from a direct request.
	await expect(direct.fetch(at("/jwks"))).rejects.toMatchObject({ reason: "special-address" });
	expect(asked).toEqual([]);
	expect(resolved).toEqual(["idp.example.test"]);
});

it("sends plain http to a plain-internal pair directly, resolving it itself, never through the proxy", async () => {
	resolved.length = 0;
	const pair = "ledger.internal:9092";
	const out = paths({
		proxy: `http://127.0.0.1:${proxyPort}`,
		allow: ["ledger.internal"],
		"plain-internal": [pair],
	});
	const url = `http://${pair}/verify`;
	// The name resolves to the loopback, which a plain-internal pair never reaches: resolved here, not by the proxy.
	await expect(out.fetch(url, {}, { internal: configuredUrl(url) })).rejects.toMatchObject({
		reason: "special-address",
	});
	expect(resolved).toEqual(["ledger.internal"]);
});

it("connects directly to a dotted entry's name and the names under it, and to no other", async () => {
	const underDot = async (entry: string) => {
		asked.length = 0;
		resolved.length = 0;
		await paths({ proxy: `http://127.0.0.1:${proxyPort}`, "direct-hosts": [entry] })
			.fetch(at("/jwks"))
			.catch(() => undefined);
		return { proxied: asked.length, resolved: resolved.length };
	};
	expect(await underDot(".example.test")).toEqual({ proxied: 0, resolved: 1 });
	expect(await underDot(".idp.example.test")).toEqual({ proxied: 0, resolved: 1 });
	expect(await underDot(".other.example.test")).toEqual({ proxied: 1, resolved: 0 });
});

it("checks a destination written as an address against that address, never the proxy's", async () => {
	const out = outboundOver(
		section.parse({ "allow-any-public": true, proxy: `http://127.0.0.1:${proxyPort}` }),
		noResolving,
		{ ca: addressAuthority },
	);
	const reached = async (server: "proxy" | "public") => {
		upstreamPort = byAddress[server].port;
		return out.fetch("https://93.184.215.14:8443/").then(
			(answer) => answer.status,
			(error: unknown) => (error as Partial<OutboundUnavailable>).failure,
		);
	};
	// A certificate for the proxy's address, or for localhost, does not stand for the destination.
	expect(await reached("proxy")).toBe("unreachable");
	expect(await reached("public")).toBe(200);
});

it("closes the tunnel when the request cannot be made over it, as for a header broken across lines", async () => {
	await expect(
		viaProxy().fetch(at("/jwks"), { headers: { "x-note": "a\r\nb" } }),
	).rejects.toThrow();
	const tunnel = tunnels.at(-1) as Socket;
	const closed =
		tunnel.closed ||
		(await Promise.race([
			new Promise<boolean>((done) => tunnel.once("close", () => done(true))),
			new Promise<boolean>((done) => setTimeout(() => done(false), 1000)),
		]));
	expect(closed).toBe(true);
});

/** The failure a fetch through the proxy ends in, or what it answered. */
const failureOf = (fetching: Promise<unknown>) =>
	fetching.then(
		() => "answered",
		(error: unknown) => (isUnavailable(error) ? (error as OutboundUnavailable).failure : error),
	);

it("answers a proxy that refuses the tunnel as unavailable, proxy-refused", async () => {
	answering = "refuse";
	expect(await failureOf(viaProxy().fetch(at("/jwks")))).toBe("proxy-refused");
});

it("holds a proxy that never answers CONNECT to the one deadline, as timeout", async () => {
	answering = "stall";
	expect(await failureOf(viaProxy().fetch(at("/jwks"), {}, { timeoutMs: 100 }))).toBe("timeout");
});

it("answers a proxy it cannot reach as unreachable", async () => {
	const out = paths({ proxy: `http://127.0.0.1:${refusedPort}` });
	expect(await failureOf(out.fetch(at("/jwks")))).toBe("unreachable");
});

it("asks the proxy for an IPv6 destination in brackets, with its port", async () => {
	const out = paths({
		proxy: `http://127.0.0.1:${proxyPort}`,
		"allow-any-public": true,
		allow: [],
	});
	await failureOf(out.fetch("https://[2606:4700::1111]:8443/"));
	expect(asked.map((a) => a.target)).toEqual(["[2606:4700::1111]:8443"]);
});

it("still checks the destination's name, and an address written in the URL, before asking the proxy", async () => {
	const out = viaProxy();
	await expect(out.fetch(`https://elsewhere.example.test:${idpPort}/`)).rejects.toMatchObject({
		reason: "not-allowed",
	});
	await expect(
		paths({ proxy: `http://127.0.0.1:${proxyPort}`, "allow-any-public": true, allow: [] }).fetch(
			"https://10.0.0.1/",
		),
	).rejects.toMatchObject({ reason: "special-address" });
	expect(asked).toEqual([]);
});

it("takes a proxy only as an http origin, its credentials apart, and refuses a sample", () => {
	const refused = (settings: Record<string, unknown>) => !section.safeParse(settings).success;
	for (const url of [
		"http://user:secret@proxy.example.test:3128",
		"https://proxy.example.test:3128",
		"http://proxy.example.test:3128/path",
		"http://proxy.example.test:3128?q",
		" http://proxy.example.test:3128",
		"http://proxy.example.test:3128\n",
		"socks5://proxy.example.test:1080",
		// Written only as the URL parser writes an origin: no trailing `/`, default port or upper case.
		"http://proxy.example.test:3128/",
		"http://proxy.example.test:80",
		"http://PROXY.example.test:3128",
	]) {
		expect(refused({ proxy: url }), url).toBe(true);
		const issues = section.safeParse({ proxy: url }).error?.issues ?? [];
		expect(
			issues.map((issue) => issue.path.join(".")),
			url,
		).toEqual(["proxy"]);
		expect(JSON.stringify(issues), url).not.toContain("proxy.example.test");
	}
	expect(refused({ proxy: "http://proxy.example.test:3128" })).toBe(false);
	for (const broken of ["Basic a\r\nb", "Basic a\nb", " Basic dGVzdA==", "Basic dGVzdA== "]) {
		expect(
			refused({ proxy: "http://proxy.example.test:3128", "proxy-authorization": broken }),
			JSON.stringify(broken),
		).toBe(true);
	}
	expect(refused({ "proxy-authorization": "Basic dGVzdA==" }), "credentials without a proxy").toBe(
		true,
	);
	expect(
		refused({
			proxy: "http://proxy.example.test:3128",
			"proxy-authorization": "REPLACE-PROXY-AUTHORIZATION",
		}),
	).toBe(true);
});
