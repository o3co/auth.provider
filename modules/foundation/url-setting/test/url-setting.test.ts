import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { expect, it } from "vitest";
import { z } from "zod";
import { urlSetting } from "../src/contract.ts";

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
