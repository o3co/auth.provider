import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { urlSetting, urlsChecked } from "../src/contract.ts";

const https = urlSetting({ schemes: ["https"] });
const takes = (schema: typeof https, value: string) => schema.safeParse(value).success;

it("keeps a URL of a listed scheme and a host exactly as written", () => {
	for (const value of [
		"https://a.example",
		"https://a.example/",
		"https://a.example:8443/login?x=1",
		"https://a.example/%7Euser",
	]) {
		expect(https.parse(value)).toBe(value);
	}
	// A host may hold `$`, which a replacement string would read as a pattern.
	for (const value of ["https://a.$&", "https://a.$'?x", "https://a.$$", "https://a.$`"]) {
		expect(https.parse(value)).toBe(value);
	}
	const both = urlSetting({ schemes: ["https", "http"] });
	expect(both.parse("http://127.0.0.1:8080/x")).toBe("http://127.0.0.1:8080/x");
});

it("refuses userinfo, a fragment, whitespace, control characters and backslashes", () => {
	for (const value of [
		"https://user@a.example",
		"https://user:secret@a.example/",
		"https://@a.example",
		"https://a.example/#",
		"https://a.example/#/login",
		" https://a.example",
		"https://a.example/ x",
		"https://a.example\t",
		"https://a.example/\u0000",
		"https://a.example/\u007f",
		"https://a.example\\path",
	]) {
		expect(takes(https, value), value).toBe(false);
	}
});

// A marker in each value: a refusal names no part of it.
const marker = "mk7q";
const refusedAt = async (page: string) => {
	const section = z.strictObject({ upstream: z.strictObject({ page: https }) });
	const using = defineModule({ name: "using", section }, () => []);
	const config = { ...kernelConfig(), using: { upstream: { page } } };
	const refused = await assemble({ modules: [using], config }).catch((error: unknown) => error);
	expect(refused, page).toBeInstanceOf(BootRefused);
	return (refused as BootRefused).refusals;
};

it("refuses a URL not in the form the parser writes it, naming the key and the kind only", async () => {
	const kinds: [string, string[]][] = [
		["a scheme not in lower case", [`HTTPS://${marker}.example/${marker}`]],
		["a default port written", [`https://${marker}.example:443/${marker}`]],
		[
			"whitespace or control characters",
			[
				` https://${marker}.example/${marker}`,
				`https://${marker}.example/${marker} x`,
				`https://${marker}.example/${marker}\t`,
				`https://${marker}.example/${marker}\u0000`,
				`https://${marker}.example/${marker}\u001f`,
				`https://${marker}.example/${marker}\u007f`,
			],
		],
		[
			"the path's ending",
			[`https://${marker}.example/${marker}/.`, `https://a.example/${marker}/..`],
		],
		[
			"host case",
			[`https://${marker.toUpperCase()}.example/${marker}`, `https://[2001:DB8::1]/${marker}`],
		],
		[
			"dot segments",
			[
				`https://${marker}.example/${marker}/../x`,
				`https://${marker}.example/%2e/${marker}`,
				`https://${marker}.example/%2E/${marker}`,
			],
		],
		[
			"invisible or mapped characters",
			[
				`https://${marker}\u00ad.example/${marker}`,
				`https://${marker}\u200b.example/${marker}`,
				`https://b\u00fccher-${marker}.example/${marker}`,
				`https://${marker}\u3002example/${marker}`,
			],
		],
		["a backslash", [`https://${marker}.example\\${marker}`]],
		["percent-encoding in the host", [`https://${marker}%2Eexample/${marker}`]],
		[
			"an IP address not in its shortest form",
			[
				`https://0x7f.1/${marker}`,
				`https://0X7F.1/${marker}`,
				`https://127.1/${marker}`,
				`https://[2001:db8:0::1]/${marker}`,
			],
		],
		["an empty port", [`https://${marker}.example:/${marker}`]],
		["a leading zero in the port", [`https://${marker}.example:08443/${marker}`]],
		[
			"characters the parser percent-encodes",
			[
				`https://${marker}.example/${marker}"`,
				`https://${marker}.example/${marker}\u00e4`,
				`https://${marker}.example/x?q="${marker}"`,
				`https://${marker}.example/${marker}\u{1f600}?\u00e4%41`,
			],
		],
	];
	for (const [kind, values] of kinds) {
		for (const value of values) {
			const refusals = await refusedAt(value);
			expect(refusals, value).toEqual([
				{
					where: "using.upstream.page",
					reason: `a URL as the URL parser writes it; refused for ${kind}`,
				},
			]);
			expect(JSON.stringify(refusals).toLowerCase(), value).not.toContain(marker);
		}
	}
	expect(https.parse("https://a.example?x")).toBe("https://a.example?x");
});

it("names no part of a URL it refuses for its rules", async () => {
	for (const value of [
		`https://${marker}:${marker}@${marker}.example/`,
		`https://${marker}.example/#${marker}`,
		`https:///${marker}.example`,
		`https://${marker}.example:99999/${marker}`,
		`http://${marker}.example/${marker}`,
		`https:${marker}.example`,
	]) {
		const refusals = await refusedAt(value);
		expect(
			refusals.map((r) => r.where),
			value,
		).toEqual(["using.upstream.page"]);
		expect(JSON.stringify(refusals).toLowerCase(), value).not.toContain(marker);
	}
});

it("gives the first reason a URL is refused for", () => {
	const reason = (value: string) => https.safeParse(value).error?.issues[0]?.message;
	const form = "a URL as the URL parser writes it; refused for";
	expect(reason("https://a.example\t")).toBe(`${form} whitespace or control characters`);
	expect(reason("HTTPS://A.example:443")).toBe(`${form} a scheme not in lower case`);
	expect(reason("https://A.example:443")).toBe(`${form} host case`);
	expect(reason("https:///a.example")).toBe("a URL: a host");
	expect(reason("https://user:secret@A.example")).toBe("a URL: no userinfo");
	// The host ends at a fragment, so an `@` in the fragment is no userinfo.
	expect(reason("https://a.example#u@x")).toBe("a URL: no fragment");
	expect(reason("http://a.example")).toBe("a URL: starting https://");
});

it("refuses a scheme not listed, in upper case, or without //, and a value without a host", () => {
	for (const value of [
		"http://a.example",
		"HTTPS://a.example",
		"Https://a.example",
		"https:a.example",
		"https:/a.example",
		"https:///a.example",
		"https://",
		"https://a.example:99999",
		"ftp://a.example",
		"a.example",
	]) {
		expect(takes(https, value), value).toBe(false);
	}
});

it("refuses a query or a trailing / only where the rules say", () => {
	const issuer = urlSetting({ schemes: ["https"], trailingSlash: "refused", query: false });
	expect(takes(issuer, "https://a.example/tenant")).toBe(true);
	for (const value of ["https://a.example/", "https://a.example/tenant/", "https://a.example?x"]) {
		expect(takes(issuer, value), value).toBe(false);
	}
	expect(takes(urlSetting({ schemes: ["https"], query: false }), "https://a.example/?")).toBe(
		false,
	);
	expect(takes(https, "https://a.example/?x=1")).toBe(true);
	expect(
		takes(urlSetting({ schemes: ["https"], trailingSlash: "refused" }), "https://a.example/x?y"),
	).toBe(true);
});

it("refuses to boot with a configured URL it does not take", async () => {
	const section = z.strictObject({ page: urlSetting({ schemes: ["https"] }) });
	const using = defineModule({ name: "using", section }, () => []);
	const boot = (page: string) =>
		assemble({ modules: [using], config: { ...kernelConfig(), using: { page } } });
	await expect(boot("https://u@a.example")).rejects.toThrow(BootRefused);
	await expect(boot("https://a.example")).resolves.toBeDefined();
});

it("takes plain http beside the schemes only on a loopback host, where the rules allow it", () => {
	const local = urlSetting({ schemes: ["https"], loopbackHttp: true });
	for (const value of [
		"http://localhost",
		"http://localhost:3000/login",
		"http://127.0.0.1:3000/login?x=1",
		"http://127.255.0.1/",
		"http://[::1]:3000/login",
		"https://a.example/login",
	]) {
		expect(local.parse(value)).toBe(value);
	}
	// Without the rule, a loopback host is no exception.
	for (const value of ["http://localhost:3000/login", "http://127.0.0.1/", "http://[::1]/"]) {
		expect(takes(https, value), value).toBe(false);
	}
});

it("decides plain http's loopback host on the parser's form only, each edge refused", () => {
	const local = urlSetting({ schemes: ["https"], loopbackHttp: true });
	const reason = (value: string) => local.safeParse(value).error?.issues[0]?.message;
	const form = "a URL as the URL parser writes it; refused for";
	const cases: [string, string[]][] = [
		[
			"a URL: http only on a loopback host",
			[
				// A name that only resolves to a loopback address, or may not.
				"http://localhost./",
				"http://a.localhost/",
				"http://localhost.localdomain/",
				"http://127.0.0.1.nip.io/",
				// Every address, not a loopback one.
				"http://0.0.0.0/",
				"http://[::]/",
				// An IPv4-mapped IPv6 loopback address, in the parser's form.
				"http://[::ffff:7f00:1]/",
				"http://126.255.255.255/",
				"http://128.0.0.1/",
				"http://10.0.0.1/",
				"http://a.example/",
			],
		],
		// The parser rewrites these to a loopback address, so they are not in its form.
		[
			`${form} an IP address not in its shortest form`,
			[
				"http://127.1/",
				"http://127.0.0.1./",
				"http://0177.0.0.1/",
				"http://2130706433/",
				"http://[0:0:0:0:0:0:0:1]/",
				"http://[::ffff:127.0.0.1]/",
			],
		],
		[`${form} host case`, ["http://LOCALHOST/", "http://LocalHost:3000/"]],
		[`${form} percent-encoding in the host`, ["http://loc%61lhost/"]],
		["a URL: no userinfo", ["http://localhost@a.example/", "http://a@localhost/"]],
		[`${form} a scheme not in lower case`, ["HTTP://localhost/"]],
		[
			"a URL: starting https:// or http:// on a loopback host",
			["ftp://localhost/", "ws://127.0.0.1/", "localhost:3000"],
		],
	];
	for (const [expected, values] of cases) {
		for (const value of values) expect(reason(value), value).toBe(expected);
	}
});

it("names no part of a plain http URL it refuses for its host", async () => {
	const section = z.strictObject({ page: urlSetting({ schemes: ["https"], loopbackHttp: true }) });
	const using = defineModule({ name: "using", section }, () => []);
	const boot = (page: string) =>
		assemble({ modules: [using], config: { ...kernelConfig(), using: { page } } });
	await expect(boot("http://localhost:3000/login")).resolves.toBeDefined();
	const refused = await boot(`http://${marker}.example/${marker}`).catch((e: unknown) => e);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals).toEqual([
		{ where: "using.page", reason: "a URL: http only on a loopback host" },
	]);
});

it("takes an origin alone where the rules ask one: no path, not even /, and no query", () => {
	const origin = urlSetting({ schemes: ["https", "http"], origin: true });
	for (const value of ["https://a.example", "http://a.example:8080"]) {
		expect(takes(origin, value), value).toBe(true);
	}
	for (const value of ["https://a.example/", "https://a.example/x", "https://a.example?x"]) {
		expect(
			origin.safeParse(value).error?.issues.map((i) => i.message),
			value,
		).toEqual(["a URL: an origin alone, with no path (not even a trailing `/`) and no query"]);
	}
});

describe("URLs a section checks once they all parse", () => {
	const section = z.strictObject({
		token: urlSetting({ schemes: ["https"] }),
		keys: urlSetting({ schemes: ["https"] }).optional(),
	});
	const asked: { url: string; hosts: readonly string[] }[] = [];
	const checked = section.superRefine(
		urlsChecked(
			(url, hosts) => {
				asked.push({ url, hosts });
				return new URL(url).hostname === "bad.example" ? "refused here" : undefined;
			},
			{
				urls: (s) => [s.token, s.keys],
				sent: (s) => ({
					token: { url: s.token, hosts: [new URL(s.token).hostname] },
					keys: { url: s.keys, hosts: ["any.example"] },
				}),
			},
		),
	);
	const issues = (value: unknown) =>
		checked.safeParse(value).error?.issues.map((i) => [i.path.join("."), i.message]);

	it("puts what the check answers at each key it refuses, and asks of each URL sent", () => {
		asked.length = 0;
		expect(issues({ token: "https://bad.example/t", keys: "https://ok.example/k" })).toEqual([
			["token", "refused here"],
		]);
		expect(asked).toEqual([
			{ url: "https://bad.example/t", hosts: ["bad.example"] },
			{ url: "https://ok.example/k", hosts: ["any.example"] },
		]);
		expect(issues({ token: "https://ok.example/t" })).toBeUndefined();
	});

	it("asks nothing while a URL is no URL, leaving that to its key's own refusal", () => {
		asked.length = 0;
		const refused = urlsChecked(
			() => {
				throw new Error("asked");
			},
			{ urls: (s: { a: string }) => [s.a], sent: (s) => ({ a: { url: s.a, hosts: [] } }) },
		);
		const issued: unknown[] = [];
		refused({ a: "no url" }, { addIssue: (i: unknown) => issued.push(i) } as never);
		expect(issued).toEqual([]);
	});
});
