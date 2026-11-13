import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { policyOf } from "@mod/outbound-policy";
import { testTlsOptions } from "@mod/tls-options/testing";
import { expect, it, vi } from "vitest";
import { section } from "../../module.ts";
import type { Route } from "../../transport/transport.ts";
import { crlFetchOf } from "../crl-fetch.ts";

// A connection to a public address the test names reaches a local server instead: a direct host's
// CRL server, which a signed fetch may not reach at a loopback address.
const rerouted = vi.hoisted(() => ({ from: "8.8.8.8", to: 0 }));
vi.mock("node:net", async (original) => {
	const real = await original<typeof import("node:net")>();
	return {
		...real,
		connect: (...args: unknown[]) => {
			const options = args[0] as { host?: unknown } | null;
			if (typeof options === "object" && options?.host === rerouted.from) {
				return real.connect({ host: "127.0.0.1", port: rerouted.to });
			}
			return (real.connect as (...a: unknown[]) => ReturnType<typeof real.connect>)(...args);
		},
	};
});

const settings = section.parse({
	"allow-any-public": true,
	revocation: { hosts: ["crl.example", "direct.example"] },
});
const policy = policyOf(settings);
const tls = { floor: testTlsOptions };
const resolving = (answers: readonly string[] = ["127.0.0.1"]) => {
	const asked: string[] = [];
	return {
		asked,
		resolve: async (name: string) => {
			asked.push(name);
			return answers;
		},
	};
};
const live = () => new AbortController().signal;

it("fetches a CRL the proxy carries through it, telling the proxy's refusal apart, and a direct host's answers as before", async () => {
	const statusOf = { proxy: 200, direct: 200 };
	const servers = await Promise.all(
		(["proxy", "direct"] as const).map(async (which) => {
			const server = createServer((_req, res) => {
				res.statusCode = statusOf[which];
				res.end("crl");
			});
			await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
			return server;
		}),
	);
	const [proxyServer, directServer] = servers as [Server, Server];
	rerouted.to = (directServer.address() as AddressInfo).port;
	const { asked, resolve } = resolving(["8.8.8.8"]);
	const route: Route = {
		proxy: new URL(`http://proxy.example:${(proxyServer.address() as AddressInfo).port}`),
		resolve: async () => ["127.0.0.1"],
		direct: (host) => host === "direct.example",
	};
	const fetch = crlFetchOf(
		settings.revocation.hosts,
		policy,
		route,
		resolve,
		tls,
		AbortSignal.timeout,
	);
	const through = async (status: number) => {
		statusOf.proxy = status;
		const got = await fetch("http://crl.example/root.crl", live());
		return got instanceof Uint8Array ? "crl" : got;
	};
	expect(await through(200)).toBe("crl");
	expect([await through(403), await through(405), await through(407)]).toEqual(
		Array(3).fill("proxy-refused"),
	);
	expect([await through(502), await through(404)]).toEqual(["unreachable", "refused"]);
	// The proxy resolves the name the CRL is at; outbound only its own.
	expect(asked).toEqual([]);
	const direct = async (status: number) => {
		statusOf.direct = status;
		const got = await fetch("http://direct.example/root.crl", live());
		return got instanceof Uint8Array ? "crl" : got;
	};
	expect([await direct(200), await direct(403), await direct(502)]).toEqual([
		"crl",
		"refused",
		"unreachable",
	]);
	for (const server of servers) server.close();
});

it("fetches as signed material at the hosts listed and public addresses alone, and tells an end by its own signal", async () => {
	const { asked, resolve } = resolving();
	const fetch = crlFetchOf(
		settings.revocation.hosts,
		policy,
		undefined,
		resolve,
		tls,
		AbortSignal.timeout,
	);
	expect(await fetch("http://elsewhere.example/root.crl", live())).toBe("refused");
	expect(asked).toEqual([]);
	expect(await fetch("http://crl.example/root.crl", live())).toBe("refused");
	expect(asked).toEqual(["crl.example"]);
	const ended = new AbortController();
	ended.abort();
	expect(await fetch("http://crl.example/root.crl", ended.signal)).toBe("aborted");
});
