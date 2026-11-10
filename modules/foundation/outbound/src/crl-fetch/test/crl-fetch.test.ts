import { policyOf } from "@mod/outbound-policy";
import { testTlsOptions } from "@mod/tls-options/testing";
import { expect, it } from "vitest";
import { section } from "../../module.ts";
import type { Route } from "../../transport/transport.ts";
import { crlFetchOf } from "../crl-fetch.ts";

const settings = section.parse({
	"allow-any-public": true,
	revocation: { hosts: ["crl.example", "direct.example"] },
});
const policy = policyOf(settings);
const tls = { floor: testTlsOptions };
const resolving = () => {
	const asked: string[] = [];
	return {
		asked,
		resolve: async (name: string) => {
			asked.push(name);
			return ["127.0.0.1"];
		},
	};
};
const live = () => new AbortController().signal;

it("goes around no proxy: a CRL the proxy would carry is unreachable, nothing resolved, until it goes through the proxy", async () => {
	const { asked, resolve } = resolving();
	const route: Route = {
		proxy: new URL("http://proxy.example:3128"),
		resolve,
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
	expect(await fetch("http://crl.example/root.crl", live())).toBe("unreachable");
	expect(asked).toEqual([]);
	// A host left direct is fetched directly: here its address is no public one, so refused.
	expect(await fetch("http://direct.example/root.crl", live())).toBe("refused");
	expect(asked).toEqual(["direct.example"]);
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
