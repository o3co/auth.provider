import http from "@mod/http/module";
import { testRequest } from "@mod/http/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { cookies, cookiesFor } from "../src/contract.ts";
import cookiesModule from "../src/module.ts";

/** The cookies of a deployment at this public origin. */
async function at(origin: string) {
	const insecure = origin.startsWith("http:") ? { "insecure-origin": true } : {};
	const app = await assemble({
		modules: [http, cookiesModule],
		config: { ...kernelConfig(), http: { port: 0, "public-origin": origin, ...insecure } },
		runtime: quietRuntime(),
	});
	return app.get(cookies);
}

it("names and sets cookies by one rule, and reads one only when the request carries it once", async () => {
	const secure = await at("https://as.example");
	const carrying = (cookie: string, scheme: "http" | "https" = "https") =>
		testRequest({ headers: new Map([["cookie", cookie]]), source: { scheme } });
	expect(secure.write("s", "v", 60)).toBe(
		"__Host-s=v; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=60",
	);
	expect(secure.read(carrying("a=1; __Host-s=v"), "s")).toBe("v");
	expect(secure.read(carrying("__Host-sx=w; __Host-s=v"), "s")).toBe("v");
	expect(secure.read(carrying("s=v"), "s")).toBeUndefined();
	expect(secure.read(carrying("__Host-s=v; __Host-s=w"), "s")).toBeUndefined();
	expect(secure.read(carrying("__Host-s=v", "http"), "s")).toBeUndefined();
	const plain = await at("http://as.example");
	expect(plain.write("s", "", 0)).toBe("s=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
	expect(plain.read(carrying("s=v", "http"), "s")).toBe("v");
});

it("writes a cross-site cookie only as __Host- and Secure, and never where cookies cannot be secure", async () => {
	const secure = await at("https://as.example");
	expect(secure.write("t", "v", 600, { crossSite: true })).toBe(
		"__Host-t=v; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=600",
	);
	const plain = await at("http://as.example");
	expect(() => plain.write("t", "v", 600, { crossSite: true })).toThrow();
});

it("reads no cookie from a request that carries none", async () => {
	for (const origin of ["https://as.example", "http://as.example"]) {
		const scheme = origin.startsWith("https:") ? "https" : "http";
		expect((await at(origin)).read(testRequest({ source: { scheme } }), "s")).toBeUndefined();
	}
});

it("writes each cookie by the rule of the deployment writing it, never with a Domain", () => {
	const before = cookiesFor(true).write("s", "v", 60);
	const after = cookiesFor(false).write("s", "v", 60);
	expect(before).toBe("__Host-s=v; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=60");
	expect(after).toBe("s=v; Path=/; HttpOnly; SameSite=Lax; Max-Age=60");
	for (const written of [before, after, cookiesFor(true).write("t", "v", 0, { crossSite: true })]) {
		expect(written.toLowerCase()).not.toContain("domain=");
	}
});

it("offers cookies that a module cannot change", async () => {
	expect(Object.isFrozen(await at("https://as.example"))).toBe(true);
	expect(Object.isFrozen(cookiesFor(false))).toBe(true);
});

it("refuses to write a name or value that would change the header beyond the one cookie", () => {
	const jar = cookiesFor(true);
	for (const value of ["a;b", "a b", 'a"b', "a,b", "a\\b", "a\rb", "a\nb", "a\u0000b", "é"]) {
		expect(() => jar.write("s", value, 60)).toThrow();
	}
	for (const name of ["s;Domain=x", "s=t", "s t", ""])
		expect(() => jar.write(name, "v", 60)).toThrow();
	expect(jar.write("s", "aZ09-_.~=+/!#$%&'()*:<>?@[]^`{|}", 60)).toContain("=aZ09-_.~=+/");
});
