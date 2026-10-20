import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import {
	type OutboundRefusals,
	outboundLimits,
	outboundRefusals,
	policyOf,
	policySettings,
} from "@mod/outbound-policy";
import { configuredUrl } from "@mod/url-setting/testing";
import { afterEach, expect, it, vi } from "vitest";
import { type Narrower, outbound, signedOutbound } from "../src/contract.ts";
import outboundModule, { section } from "../src/module.ts";

afterEach(() => vi.unstubAllEnvs());

/** The proxy variables blanked, but for `name`, set to a proxy when given. */
const onlyProxy = (name?: string) => {
	vi.unstubAllEnvs();
	for (const variable of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]) {
		vi.stubEnv(variable, "");
		vi.stubEnv(variable.toLowerCase(), "");
	}
	if (name) vi.stubEnv(name, "http://proxy.test:3128");
};

const boot = (settings: Record<string, unknown> = {}) =>
	assemble({ modules: [outboundModule], config: { ...kernelConfig(), outbound: settings } });

it("holds to the defaults: outbound-policy's for its keys, and outbound's own", () => {
	expect(section.parse({})).toEqual({
		...policySettings.parse({}),
		"max-concurrent": 16,
		"direct-despite-proxy": false,
		"direct-hosts": [],
	});
});

it("takes each cap within its range, a size or time written with its unit, and refuses anything else", () => {
	for (const bad of [
		{ "max-response-size": "0B" },
		{ "max-response-size": "16777217B" },
		{ "max-response-size": 1024 },
		{ "max-response-size": "1024" },
		{ "signed-max-response-size": "0B" },
		{ "signed-max-response-size": "16777217B" },
		{ timeout: "0ms" },
		{ timeout: "60001ms" },
		{ timeout: "1.5ms" },
		{ timeout: 5000 },
		{ timeout: "5000" },
		{ "max-concurrent": 0 },
		{ "max-concurrent": 1025 },
		{ "max-concurrent": 1.5 },
	]) {
		expect(section.safeParse(bad).success, JSON.stringify(bad)).toBe(false);
	}
	expect(
		section.safeParse({
			"max-response-size": "1B",
			"signed-max-response-size": "1B",
			timeout: "1ms",
			"max-concurrent": 1,
		}).success,
	).toBe(true);
	expect(
		section.safeParse({
			"max-response-size": "16MiB",
			"signed-max-response-size": "16MiB",
			timeout: "1m",
			"max-concurrent": 1024,
		}).success,
	).toBe(true);
});

it("refuses allow beside allow-any-public, and a key it does not know", () => {
	for (const bad of [
		{ allow: ["a.example"], "allow-any-public": true },
		{ allowed: ["a.example"] },
	]) {
		expect(section.safeParse(bad).success, JSON.stringify(bad)).toBe(false);
	}
});

it("takes only hosts in allow and deny, and host:port pairs in plain-loopback", () => {
	for (const entry of [
		"a.example",
		".example",
		"Example.COM.",
		"[2001:DB8::1]",
		"2001:db8::1",
		"10.0.0.1",
	]) {
		expect(section.safeParse({ deny: [entry] }).success, entry).toBe(true);
		expect(section.safeParse({ allow: [entry] }).success, entry).toBe(true);
	}
	for (const entry of [
		"",
		"a..example",
		"bad host",
		"*.example",
		"*.",
		"*.*.example",
		"*",
		"https://a.example",
		"a.example/x",
		"a.example:8443",
		"[2001:db8::1]:8443",
		"u@a.example",
		"a.example?q",
		"a.example#f",
		"a.example\\x",
	]) {
		expect(section.safeParse({ deny: [entry] }).success, entry).toBe(false);
		expect(section.safeParse({ allow: [entry] }).success, entry).toBe(false);
	}
	for (const pair of ["localhost:8080", "[::1]:8080", "127.0.0.1:65535"]) {
		expect(section.safeParse({ "plain-loopback": [pair] }).success, pair).toBe(true);
	}
	for (const pair of [
		"localhost",
		"a..b:8080",
		"bad host:8080",
		"localhost:65536",
		"localhost:08080",
		"localhost:0",
		"localhost:",
		"a/b:80",
		"*.a.example:80",
	]) {
		expect(section.safeParse({ "plain-loopback": [pair] }).success, pair).toBe(false);
	}
});

it("refuses to boot while a proxy is set, unless told to go direct", async () => {
	for (const name of ["HTTP_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]) {
		onlyProxy(name);
		const refused = await boot().then(
			() => undefined,
			(error: unknown) => error,
		);
		expect(refused, name).toBeInstanceOf(BootRefused);
		// It names the variable, never its value, and the two ways on.
		const [{ reason } = { reason: "" }] = (refused as BootRefused).refusals;
		expect(reason).toContain(name);
		expect(reason).toContain("outbound.proxy");
		expect(reason).toContain("direct-despite-proxy");
		expect(reason).not.toContain("proxy.test");
		const app = await boot({ "direct-despite-proxy": true });
		expect(app.get(outbound)).toBeDefined();
	}
});

it("boots with a proxy configured whatever the variables say, and warns what it leaves to the proxy", async () => {
	onlyProxy("HTTPS_PROXY");
	const recorded = recordingLog();
	const withProxy = (outboundSettings: Record<string, unknown>) =>
		assemble({
			modules: [outboundModule],
			config: { ...kernelConfig(), outbound: outboundSettings },
			runtime: quietRuntime({ log: recorded.log }),
		});
	const warned = () => recorded.lines().map((line) => line.event);
	await withProxy({ proxy: "http://127.0.0.1:3128", "proxy-authorization": "Basic dGVzdA==" });
	expect(warned()).toEqual(["outbound.proxy_checks_addresses"]);
	await withProxy({
		proxy: "http://proxy.example.test:3128",
		"proxy-authorization": "Basic dGVzdA==",
	});
	// Credentials to a proxy over plain http, past the loopback, go in clear.
	expect(warned().slice(1)).toEqual([
		"outbound.proxy_checks_addresses",
		"outbound.proxy_credentials_in_clear",
	]);
	// A name that only begins like a loopback address is no loopback.
	await withProxy({
		proxy: "http://127.example.test:3128",
		"proxy-authorization": "Basic dGVzdA==",
	});
	expect(warned().slice(3)).toEqual([
		"outbound.proxy_checks_addresses",
		"outbound.proxy_credentials_in_clear",
	]);
	expect(JSON.stringify(recorded.lines())).not.toContain("dGVzdA==");
});

it("warns at each boot that names plain-internal pairs, telling their count alone", async () => {
	const recorded = recordingLog();
	const booted = (outboundSettings: Record<string, unknown>) =>
		assemble({
			modules: [outboundModule],
			config: { ...kernelConfig(), outbound: outboundSettings },
			runtime: quietRuntime({ log: recorded.log }),
		});
	await booted({});
	expect(recorded.lines()).toEqual([]);
	await booted({ "plain-internal": ["ledger.internal:9092", "keys.internal:8080"] });
	expect(recorded.lines().map((line) => [line.level, line.event, line.fields])).toEqual([
		["warn", "outbound.plain_internal", { count: 2 }],
	]);
	expect(JSON.stringify(recorded.lines())).not.toContain("internal:");
});

it("boots on many instances, holding nothing they would need to share", async () => {
	const config = { ...kernelConfig({ deployment: "multi" }), outbound: {} };
	await expect(assemble({ modules: [outboundModule], config })).resolves.toBeDefined();
});

it("boots without a proxy, and refuses a destination before sending", async () => {
	onlyProxy();
	const app = await boot({ deny: ["example.com"] });
	await expect(app.get(outbound).fetch("https://example.com/")).rejects.toMatchObject({
		reason: "denied",
	});
	await expect(
		app.get(signedOutbound).fetch("http://example.com/", {}, { hosts: ["example.com"] }),
	).rejects.toMatchObject({ reason: "denied" });
	// Each contract answers through its own path: plain http is signed material's alone.
	const open = await boot({ "allow-any-public": true });
	await expect(open.get(outbound).fetch("http://10.0.0.1/")).rejects.toMatchObject({
		reason: "scheme",
	});
	await expect(
		open.get(signedOutbound).fetch("http://10.0.0.1/", {}, { hosts: ["10.0.0.1"] }),
	).rejects.toMatchObject({ reason: "special-address" });
});

it("answers at boot where a request is cut, as fetch cuts it: the caps narrowed, never widened", async () => {
	onlyProxy();
	const limits = (
		await boot({ "allow-any-public": true, timeout: "2s", "max-response-size": "1KiB" })
	).get(outboundLimits);
	expect(limits.of()).toEqual({ timeoutMs: 2000, maxBytes: 1024 });
	expect(limits.of({ timeoutMs: 500, maxBytes: 99_999 })).toEqual({
		timeoutMs: 500,
		maxBytes: 1024,
	});
	expect(() => limits.of({ timeoutMs: 0 })).toThrow(RangeError);
});

it("answers at boot why the policy refuses a URL, or nothing when it lets it through", async () => {
	onlyProxy();
	/** The reason an explanation leads with. */
	const reasonOf = (p: OutboundRefusals, url: string, n?: Narrower) =>
		p.explained(url, n)?.split(":")[0];
	const named = (
		await boot({ allow: ["api.example", "127.0.0.1"], "plain-loopback": ["127.0.0.1:8080"] })
	).get(outboundRefusals);
	const answers = (policy: typeof named, urls: Record<string, string | undefined>) =>
		Object.fromEntries(Object.keys(urls).map((url) => [url, reasonOf(policy, url)]));
	const asNamed = {
		"https://api.example/x": undefined,
		"https://other.example/": "not-allowed",
		"http://api.example/": "scheme",
		"https://u:p@api.example/": "userinfo",
		"https://api.example:0/": "port",
		"http://127.0.0.1:8080/": undefined,
		"http://127.0.0.1:8081/": "scheme",
		"ftp://api.example/": "scheme",
	};
	expect(answers(named, asNamed)).toEqual(asNamed);
	expect(reasonOf(named, "https://api.example/", { hosts: ["other.example"] })).toBe("not-allowed");
	const any = (await boot({ "allow-any-public": true, deny: ["bad.example"] })).get(
		outboundRefusals,
	);
	const asAny = {
		"https://name.example/": undefined,
		"https://bad.example/": "denied",
		"https://10.0.0.1/": "special-address",
		"https://[::ffff:127.0.0.1]/": "special-address",
		"https://93.184.215.14/": undefined,
	};
	expect(answers(any, asAny)).toEqual(asAny);
	// A private address written in the URL passes for an internal host the caller names as its operator's.
	const inside = (
		await boot({ "allow-any-public": true, "internal-hosts": ["10.0.0.5", "127.0.0.1"] })
	).get(outboundRefusals);
	expect(
		reasonOf(inside, "https://10.0.0.5/", { internal: configuredUrl("https://10.0.0.5/") }),
	).toBeUndefined();
	expect(reasonOf(inside, "https://10.0.0.5/")).toBe("special-address");
	expect(
		reasonOf(inside, "https://10.0.0.6/", { internal: configuredUrl("https://10.0.0.6/") }),
	).toBe("special-address");
	expect(
		reasonOf(inside, "https://127.0.0.1/", { internal: configuredUrl("https://127.0.0.1/") }),
	).toBe("special-address");
});

it("explains at boot why the policy refuses a URL by the keys that let it through, naming no value", async () => {
	onlyProxy();
	const rules = {
		allow: ["api.example", "127.0.0.1"],
		"plain-loopback": ["127.0.0.1:8080"],
		deny: ["bad.example"],
	};
	const named = (await boot(rules)).get(outboundRefusals);
	const allow = "not-allowed: name the host in outbound.allow, or set outbound.allow-any-public";
	// The policy's own words for plain http, which outbound-policy's tests hold: outbound hands them on.
	const plain = policyOf(policySettings.parse(rules)).explain("http://api.example/");
	const expected: Record<string, string | undefined> = {
		"https://api.example/x": undefined,
		"https://other.example/": allow,
		"http://api.example/": plain,
		"http://127.0.0.1:8081/": plain,
		"ftp://api.example/": "scheme: only https and http URLs are reached",
		"https://u:p@api.example/": "userinfo: write the URL without a user or password",
		"https://api.example:0/": "port: the URL's port is one outbound never reaches",
		"https://bad.example/": "denied: the host matches outbound.deny",
	};
	for (const [url, text] of Object.entries(expected)) expect(named.explained(url), url).toBe(text);
	// A host the caller does not name for this URL is no operator's key to set.
	expect(named.explained("https://api.example/", { hosts: ["other.example"] })).toBe(
		"not-allowed: the host is not one the setting may reach",
	);
	const any = (await boot({ "allow-any-public": true, "internal-hosts": ["10.0.0.5"] })).get(
		outboundRefusals,
	);
	expect(any.explained("https://10.0.0.6/")).toBe(
		"special-address: the URL names a special-purpose address, which outbound never reaches",
	);
	expect(any.explained("https://10.0.0.6/", { internal: configuredUrl("https://10.0.0.6/") })).toBe(
		"special-address: the URL names a special-purpose address; a private one is reached only when outbound.internal-hosts names its host",
	);
	expect(
		any.explained("https://10.0.0.5/", { internal: configuredUrl("https://10.0.0.5/") }),
	).toBeUndefined();
	// The value is never told: no host, port or pair is in any explanation.
	for (const url of Object.keys(expected)) {
		for (const value of [
			"api.example",
			"other.example",
			"bad.example",
			"127.0.0.1",
			"8081",
			"u:p",
		]) {
			expect(named.explained(url) ?? "", url).not.toContain(value);
		}
	}
});

it("takes the same host list in direct-hosts and internal-hosts, and refuses a wildcard, a dot before an address and an empty label", () => {
	for (const key of ["direct-hosts", "internal-hosts"]) {
		expect(section.safeParse({ [key]: ["a.example", ".a.example", "10.0.0.5"] }).success).toBe(
			true,
		);
		for (const entry of ["*.a.example", "*", ".10.0.0.5", "a..example"]) {
			expect(section.safeParse({ [key]: [entry] }).success, `${key} ${entry}`).toBe(false);
		}
	}
});
