import type { Client, Section } from "@mod/clients";
import { describe, expect, it } from "vitest";
import {
	answerTo,
	matches,
	redirects,
	redirectsAt,
	redirectsCopy,
	redirectsShown,
	registrable,
} from "../src/contract.ts";

/** A client whose `authorize` section registers these redirect URIs. */
const registering = (uris: readonly string[]): Client => ({
	id: "app",
	kind: "public",
	method: "none",
	registered: true,
	section: <T>(section: Section<T>) =>
		(section.name === "authorize" ? { "redirect-uris": uris } : {}) as T,
});

it("tells whether an origin is the scheme, host and port of one of the client's redirect URIs", () => {
	const client = registering([
		"https://app.example/cb",
		"http://127.0.0.1:8080/cb",
		"com.example.app:/cb",
	]);
	const cases: Record<string, [string, boolean]> = {
		"the same origin": ["https://app.example", true],
		"a loopback one with its port": ["http://127.0.0.1:8080", true],
		"another host": ["https://other.example", false],
		"another scheme": ["http://app.example", false],
		"another port": ["https://app.example:8443", false],
		"a loopback one on another port": ["http://127.0.0.1:9090", false],
		"the origin a private-use scheme has": ["null", false],
	};
	for (const [name, [origin, answer]] of Object.entries(cases)) {
		expect(redirectsAt(client, origin), name).toBe(answer);
	}
	expect(redirectsAt(registering([]), "https://app.example")).toBe(false);
});

it("answers no for a client whose record holds no authorize section, as where authorize is not composed", () => {
	const bare: Client = { ...registering([]), section: <T>() => undefined as T };
	expect(redirectsAt(bare, "https://app.example")).toBe(false);
});

describe("redirect URIs as a page shows them", () => {
	const shown = (...uris: string[]) => redirectsShown(registering(uris));

	it("shows a web host as the URL parser writes it, with a port only other than the default", () => {
		expect(
			shown(
				"https://app.example/cb",
				"https://APP2.Example:443/cb",
				"https://app.example:8443/cb?x=1",
			),
		).toEqual([
			{ host: "app.example", kind: "web" },
			{ host: "app2.example", kind: "web" },
			{ host: "app.example:8443", kind: "web" },
		]);
	});

	it("shows a name beyond ASCII as its A-label, never the U-label", () => {
		expect(shown("https://bücher.example/cb")).toEqual([
			{ host: "xn--bcher-kva.example", kind: "web" },
		]);
		expect(shown("https://xn--bcher-kva.example/cb")).toEqual([
			{ host: "xn--bcher-kva.example", kind: "web" },
		]);
	});

	it("reads loopback from the parsed host, whichever scheme or spelling the URI uses", () => {
		for (const [uri, host] of [
			["http://localhost:3000/cb", "localhost:3000"],
			["http://127.0.0.1/cb", "127.0.0.1"],
			["http://[::1]:9000/cb", "[::1]"],
			["https://localhost/cb", "localhost"],
			["https://app.localhost/cb", "app.localhost"],
			["https://127.1/cb", "127.0.0.1"],
			["https://2130706433/cb", "127.0.0.1"],
			["https://[::ffff:7f00:1]/cb", "[::ffff:7f00:1]"],
		] as const) {
			expect(shown(uri), uri).toEqual([{ host, kind: "loopback" }]);
		}
		for (const uri of ["https://localhost.redirect.example/cb", "https://127.0.0.1.example/cb"]) {
			expect(shown(uri)[0]?.kind, uri).toBe("web");
		}
	});

	it("shows a port only where it decides a match: never for a loopback literal over http, always for a name", () => {
		for (const [uri, host] of [
			["http://127.0.0.1:8080/cb", "127.0.0.1"],
			["http://127.0.0.2:8080/cb", "127.0.0.2"],
			["http://[::1]:8080/cb", "[::1]"],
			["http://localhost:8080/cb", "localhost:8080"],
			["https://localhost:8443/cb", "localhost:8443"],
			["https://127.0.0.1:8443/cb", "127.0.0.1:8443"],
		] as const) {
			expect(shown(uri), uri).toEqual([{ host, kind: "loopback" }]);
		}
	});

	it("shows two URIs alike wherever one matches the other, and apart where a port tells them apart", () => {
		const uris = [
			"http://127.0.0.1/cb",
			"http://127.0.0.1:8080/cb",
			"http://127.0.0.1:9090/cb",
			"http://[::1]/cb",
			"http://[::1]:8080/cb",
			"http://localhost/cb",
			"http://localhost:8080/cb",
			"http://localhost:9090/cb",
			"https://localhost:8443/cb",
			"https://127.0.0.1:8443/cb",
			"https://127.0.0.1:9443/cb",
			"https://app.example/cb",
			"https://app.example:8443/cb",
		];
		const pairs = uris.flatMap((a) => uris.map((b) => [a, b] as const));
		for (const [a, b] of pairs.filter(([a, b]) => matches(a, b))) {
			expect(shown(a), `${a} and ${b}`).toEqual(shown(b));
		}
		// The check above is about something: these match across ports, and these do not.
		expect(matches("http://127.0.0.1:8080/cb", "http://127.0.0.1:9090/cb")).toBe(true);
		expect(matches("http://[::1]:8080/cb", "http://[::1]/cb")).toBe(true);
		for (const [a, b] of [
			["http://localhost:8080/cb", "http://localhost:9090/cb"],
			["https://127.0.0.1:8443/cb", "https://127.0.0.1:9443/cb"],
			["https://app.example/cb", "https://app.example:8443/cb"],
		] as const) {
			expect(matches(a, b), `${a} and ${b}`).toBe(false);
			expect(shown(a), `${a} and ${b}`).not.toEqual(shown(b));
		}
	});

	it("shows a private-use scheme alone, whatever authority it writes", () => {
		expect(shown("com.example.app:/cb")).toEqual([{ host: "com.example.app", kind: "app" }]);
		expect(shown("com.example.app://redirect.example/cb")).toEqual([
			{ host: "com.example.app", kind: "app" },
		]);
	});

	it("shows each destination once, in the order first written, and every one", () => {
		expect(
			shown(
				"https://app.example/a",
				"com.example.app:/cb",
				"https://app.example/b",
				"http://127.0.0.1:1/cb",
				"http://127.0.0.1:2/cb",
				"com.example.app:/other",
			),
		).toEqual([
			{ host: "app.example", kind: "web" },
			{ host: "com.example.app", kind: "app" },
			{ host: "127.0.0.1", kind: "loopback" },
		]);
		expect(shown()).toEqual([]);
	});

	it("shows none for a client read where the section is not composed", () => {
		const bare: Client = { ...registering([]), section: <T>() => undefined as T };
		expect(redirectsShown(bare)).toEqual([]);
	});
});

it("registers https, http to localhost or loopback literals, and reverse-domain app schemes only [rfc9700-2.6-c] [oidc-core-3.1.2.1-w] [rfc9700-4.1.3-a]", () => {
	for (const ok of [
		"https://app.example/cb",
		"http://localhost:8080/cb",
		"http://127.0.0.2/cb",
		"http://[::1]:9000/cb",
		"com.example.app:/cb",
		"com.example.app://cb",
		"HTTPS://app.example/cb",
	]) {
		expect(registrable(ok)).toBe(true);
	}
	for (const bad of [
		"https:app.example/cb",
		"https:/app.example/cb",
		"https:\\\\app.example/cb",
		"HTTPS:app.example/cb",
		"http://app.example/cb",
		"http://localhost.example/cb",
		"myapp:/cb",
		"javascript:alert(1)",
		"javascript.foo:/x",
		"data:text/html,x",
		"file:///x",
		"urn:ietf:wg:oauth:2.0:oob",
	]) {
		expect(registrable(bad)).toBe(false);
	}
	expect(matches("http://127.0.0.2:9000/cb", "http://127.0.0.2/cb")).toBe(true);
	expect(matches("http://127.0.0.1:9000/cb", "http://127.0.0.2:9000/cb")).toBe(false);
	expect(matches("http://localhost:8080/cb", "http://localhost:9999/cb")).toBe(false);
});

it("compares a redirect URI with a registered one as an exact string, but for the port of a loopback IP literal, as RFC 9700 §2.1 updates the exact match [oidc-core-3.1.2.1-f] [rfc9700-2.1-a] [rfc9700-4.1.3-a]", () => {
	const registered = "https://app.example/cb";
	expect(matches(registered, registered)).toBe(true);
	for (const sent of [
		"https://app.example/cb/",
		"https://APP.example/cb",
		"https://app.example/cb?x=1",
		"https://app.example:443/cb",
		"https://app.example/Cb",
	]) {
		expect(matches(registered, sent), sent).toBe(false);
	}
	// A native app's loopback IP literal takes any port, and nothing else is let go.
	expect(matches("http://127.0.0.1/cb", "http://127.0.0.1:51004/cb")).toBe(true);
	expect(matches("http://[::1]:9000/cb", "http://[::1]:7111/cb")).toBe(true);
	expect(matches("http://127.0.0.1/cb", "http://127.0.0.1:51004/cb/")).toBe(false);
	expect(matches("http://localhost:8080/cb", "http://localhost:9999/cb")).toBe(false);
});

it("refuses to register redirect URIs with a fragment, userinfo, control characters or answer names [rfc6749-3.1.2-a] [rfc6749-3.1.2-c]", () => {
	expect(registrable("https://app.example/cb?x=1")).toBe(true);
	for (const bad of [
		"https://app.example/cb#f",
		"https://u:p@app.example/cb",
		"https://app.example/c\nb",
		"https://app.example/cb?code=1",
		"https://app.example/cb?state=1",
		"/relative",
		"https://app.example/c b",
	]) {
		expect(registrable(bad)).toBe(false);
	}
});

it("adds the answer's parameters to the redirect URI's own query, leaving out one without a value [rfc6749-3.1.2-b]", () => {
	expect(answerTo("https://app.example/cb", { code: "c", state: undefined })).toBe(
		"https://app.example/cb?code=c",
	);
	expect(answerTo("https://app.example/cb?x=1", { error: "access_denied" })).toBe(
		"https://app.example/cb?x=1&error=access_denied",
	);
});

it("writes the answer's values as UTF-8, percent-escaped [rfc6749-B-a]", () => {
	expect(answerTo("https://app.example/cb", { state: "é 東/&=" })).toBe(
		"https://app.example/cb?state=%C3%A9+%E6%9D%B1%2F%26%3D",
	);
});

describe("redirect-uris: the copy client-documents collects", () => {
	const from = { id: "https://app.example/c", host: "app.example" };
	it("copies redirect_uris under the section's own key, as given, for the schema to check", async () => {
		expect(redirectsCopy.section).toBe(redirects);
		expect(redirectsCopy.reads).toEqual(["redirect_uris"]);
		const uris = ["https://app.example/cb", "http://app.example/cb"];
		expect(redirectsCopy.copy({ redirect_uris: uris, client_name: "App" }, from)).toEqual({
			value: { "redirect-uris": uris },
		});
		const odd = { "a-key-of-the-document": "x" };
		expect(redirectsCopy.copy({ redirect_uris: odd }, from)).toEqual({
			value: { "redirect-uris": odd },
		});
		const checked = await redirects.schema["~standard"].validate({ "redirect-uris": odd });
		expect(checked.issues?.map((issue) => issue.path)).toEqual([["redirect-uris"]]);
	});

	it("copies nothing from a document without redirect_uris", () => {
		expect(redirectsCopy.copy({ client_name: "App" }, from)).toBeUndefined();
	});
});
