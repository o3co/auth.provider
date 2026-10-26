import type { Client, Section } from "@mod/clients";
import { describe, expect, it } from "vitest";
import {
	answerTo,
	matches,
	redirects,
	redirectsAt,
	redirectsCopy,
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

it("registers https, http to localhost or loopback literals, and reverse-domain app schemes only [rfc9700-2.6-c] [oidc-core-3.1.2.1-w] [rfc9700-4.1.3-a]", () => {
	for (const ok of [
		"https://app.example/cb",
		"http://localhost:8080/cb",
		"http://127.0.0.2/cb",
		"http://[::1]:9000/cb",
		"com.example.app:/cb",
		"com.example.app://cb",
	]) {
		expect(registrable(ok)).toBe(true);
	}
	for (const bad of [
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
