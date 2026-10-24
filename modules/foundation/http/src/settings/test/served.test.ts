import { certificateForwarding } from "@mod/client-certificate";
import { BootRefused } from "@mod/kernel";
import { urlSetting } from "@mod/url-setting";
import { describe, expect, it } from "vitest";
import { type HttpRequest, listening, site } from "../../contract.ts";
import { boot, handlers, serveWith, warning } from "../../serving/test/serve.ts";

it("says it is reached through a proxy only when it trusts one", async () => {
	expect((await boot()).get(site).proxied).toBe(false);
	expect((await boot({ "trusted-proxies": ["10.0.0.0/8"] })).get(site).proxied).toBe(true);
});

it("states the public origin it was given, and refuses one with a path", async () => {
	const app = await boot({ "public-origin": "https://as.example" });
	expect(app.get(site).origin).toBe("https://as.example");
	expect(app.get(site).secureCookies).toBe(true);
	expect(Object.isFrozen(app.get(site))).toBe(true);
	for (const origin of ["https://as.example/x", "ws://as.example", "ftp://as.example"]) {
		await expect(boot({ "public-origin": origin }), origin).rejects.toThrow(BootRefused);
	}
});

it("takes origins as url-setting does: an origin alone, in the form the parser writes it, with no pattern", async () => {
	const refusals = (http: Record<string, unknown>) =>
		boot(http).then(
			() => [],
			(error: BootRefused) => error.refusals,
		);
	const alone = "a URL: an origin alone, with no path (not even a trailing `/`) and no query";
	expect(await refusals({ "public-origin": "https://as.example/" })).toEqual([
		{ where: "http.public-origin", reason: alone },
	]);
	// A CORS origin is refused in url-setting's own words, each in full, and a pattern in http's.
	const origin = urlSetting({ schemes: ["https"], origin: true });
	for (const url of [
		"https://App.example",
		"https://app.example:443",
		"https://as.example/",
		"https://app.example/x",
		"http://app.example",
	]) {
		const said = origin.safeParse(url).error?.issues.map((issue) => issue.message) ?? [];
		expect(said.length, url).toBeGreaterThan(0);
		expect(await refusals({ "cors-origins": [url] }), url).toEqual(
			said.map((reason) => ({ where: "http.cors-origins.0", reason })),
		);
	}
	expect(await refusals({ "cors-origins": ["https://*.example"] })).toEqual([
		{ where: "http.cors-origins.0", reason: "an exact origin, without a pattern" },
	]);
});

it("refuses an empty or unparsable public origin or CORS origin at boot, never throwing on it", async () => {
	for (const origin of ["", "not a url", "https://"]) {
		await expect(boot({ "public-origin": origin }), `public ${origin}`).rejects.toThrow(
			BootRefused,
		);
		await expect(boot({ "cors-origins": [origin] }), `cors ${origin}`).rejects.toThrow(BootRefused);
	}
});

it("refuses a plain-http public origin unless it is accepted explicitly, and then says cookies cannot be secure", async () => {
	await expect(boot({ "public-origin": "http://as.example" })).rejects.toThrow(BootRefused);
	const app = await boot({ "public-origin": "http://as.example", "insecure-origin": true });
	expect(app.get(site).secureCookies).toBe(false);
});

it("refuses a port an environment variable gives empty, signed, fractional or not in decimal", async () => {
	for (const port of ["", " ", "-1", "+80", "1.5", "0x1f90", 1.5, -1, true]) {
		await expect(boot({ port }), JSON.stringify(port)).rejects.toBeInstanceOf(BootRefused);
	}
	expect((await boot({ port: "8080" })).get(listening)).toBeDefined();
});

it("refuses a key its section does not know", async () => {
	await expect(boot({ "trusted-proxy": ["127.0.0.1"] })).rejects.toThrow(BootRefused);
});

describe("the client's certificate", () => {
	const der = Uint8Array.from([48, 3, 2, 1, 1]);
	const sent = { "client-cert": `:${Buffer.from(der).toString("base64")}:` };
	let seen: HttpRequest["source"]["clientCertificate"];
	const reading = handlers([
		{
			method: "GET",
			path: "/",
			handle: (request) => {
				seen = request.source.clientCertificate;
				return { status: 204 };
			},
		},
	]);
	const forwarding = (trusted: string[]) => ({
		"trusted-proxies": trusted,
		"client-certificate": { dialect: "rfc9440" },
	});

	it("is handed to a handler as a trusted proxy forwards it, with no warning", async () => {
		const { runtime, count } = warning();
		await fetch(await serveWith(reading, forwarding(["127.0.0.1"]), runtime), { headers: sent });
		expect(seen).toEqual({ kind: "certificate", leaf: der, chain: [] });
		expect(count("http.client_certificate_ignored")).toBe(0);
	});

	it("is ignored from a peer not trusted, with a warning once a minute", async () => {
		const { runtime, count } = warning();
		const base = await serveWith(reading, forwarding([]), runtime);
		await fetch(base, { headers: sent });
		expect(seen).toBeUndefined();
		await fetch(base, { headers: sent });
		expect(count("http.client_certificate_ignored")).toBe(1);
	});

	it("is read where the operator names it, in a form it names", async () => {
		const forwarded = (certificate: unknown) => boot({ "client-certificate": certificate });
		await expect(forwarded({ dialect: "rfc9440" })).resolves.toBeDefined();
		await expect(forwarded({ dialect: "pem", header: "x-client-cert" })).resolves.toBeDefined();
		const xfcc = await forwarded({ dialect: "xfcc" });
		expect(xfcc.get(certificateForwarding)).toEqual({ configured: true });
		expect((await boot()).get(certificateForwarding)).toEqual({ configured: false });
		for (const bad of [
			{ dialect: "pem" },
			{ dialect: "der" },
			{ dialect: "rfc9440", header: "Bad Name" },
			{ dialect: "xfcc", "chain-header": "x-chain" },
		]) {
			await expect(forwarded(bad), JSON.stringify(bad)).rejects.toBeInstanceOf(BootRefused);
		}
	});
});
