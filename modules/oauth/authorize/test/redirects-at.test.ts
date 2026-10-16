import type { Client, Section } from "@mod/clients";
import { expect, it } from "vitest";
import { redirectsAt } from "../src/contract.ts";

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
