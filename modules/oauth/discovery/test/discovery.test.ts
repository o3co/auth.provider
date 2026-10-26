import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, BootRefused, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import { afterEach, expect, it } from "vitest";
import discovery from "../src/module.ts";

const runtime = quietRuntime();
let stop = async () => {};
afterEach(() => stop());

const item = (name: string, value: unknown) =>
	defineModule({ name: `item-${name}`, takes: [] }, (m) => [
		m.contribute(metadata).by(() => ({ name, value })),
	]);

/** discovery beside http, keys and issuer, with these modules besides. */
const composition = (extra: Module[], url = "https://as.example", corsOrigins: string[] = []) => ({
	modules: [http, keysModule, issuerModule, discovery, ...extra],
	config: {
		...kernelConfig(),
		...httpConfig(corsOrigins.length > 0 ? { "cors-origins": corsOrigins } : {}),
		...keysConfig(),
		...issuerConfig({ url }),
	},
	runtime,
});

async function serve(extra: Module[], url = "https://as.example", corsOrigins: string[] = []) {
	const app = await assemble(composition(extra, url, corsOrigins));
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	return async (path: string, method = "GET", origin?: string) => {
		const headers = { host: "elsewhere.example", ...(origin ? { origin } : {}) };
		const res = await fetch(`${base}${path}`, { method, headers });
		return {
			status: res.status,
			allowed: res.headers.get("access-control-allow-origin"),
			body: res.status === 200 ? await res.json() : undefined,
		};
	};
}

it("serves one document at both well-known names, the configured issuer first and each contributed member [oidc-discovery-3-a] [oidc-discovery-4-a] [oidc-discovery-4.1-a] [oidc-discovery-4.3-a] [rfc8414-2-a] [rfc8414-3.1-a] [rfc8414-3.3-a]", async () => {
	const get = await serve([
		item("b_supported", ["x"]),
		item("a_endpoint", "https://as.example/a"),
		item("gone", undefined),
		item("left", undefined),
	]);
	const expected = {
		issuer: "https://as.example",
		b_supported: ["x"],
		a_endpoint: "https://as.example/a",
	};
	for (const path of [
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration/",
	]) {
		const res = await get(path);
		expect(res.status).toBe(200);
		expect(res.body).toEqual(expected);
		expect(Object.keys(res.body as object)[0]).toBe("issuer");
	}
	expect((await get("/.well-known/openid-configuration", "POST")).status).not.toBe(200);
	expect((await get("/.well-known/openid-configuration/x")).status).toBe(404);
});

it("answers for an issuer with a path where RFC 8414 inserts the well-known name and where OpenID appends it, and not at the root [oidc-discovery-4-a] [oidc-discovery-4.3-a] [rfc8414-3-a] [rfc8414-3.1-a] [rfc8414-3.3-a]", async () => {
	const get = await serve([], "https://as.example/tenant/a");
	for (const path of [
		"/.well-known/oauth-authorization-server/tenant/a",
		"/.well-known/oauth-authorization-server/tenant/a/",
		"/tenant/a/.well-known/openid-configuration",
		"/tenant/a/.well-known/openid-configuration/",
	]) {
		const res = await get(path);
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ issuer: "https://as.example/tenant/a" });
	}
	// A document at the root names the issuer without the path, which a client must refuse.
	expect((await get("/.well-known/openid-configuration")).status).toBe(404);
	expect((await get("/.well-known/oauth-authorization-server")).status).toBe(404);
	expect((await get("/tenant/a/.well-known/oauth-authorization-server")).status).toBe(404);
});

it("refuses to start when two modules contribute one member", async () => {
	const refused = (extra: Module[]) =>
		serve(extra).then(
			() => false,
			(error) => error instanceof BootRefused,
		);
	expect(
		await refused([
			item("same", 1),
			defineModule({ name: "again", takes: [] }, (m) => [
				m.contribute(metadata).by(() => ({ name: "same", value: 2 })),
			]),
		]),
	).toBe(true);
});

it("lets a listed origin's page read the document at each of its names, and no other origin's [oidc-discovery-4-d]", async () => {
	const get = await serve([], "https://as.example", ["https://app.example"]);
	for (const path of [
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
	]) {
		expect((await get(path, "GET", "https://app.example")).allowed, path).toBe(
			"https://app.example",
		);
		expect((await get(path, "GET", "https://evil.example")).allowed, path).toBeNull();
	}
});

it("takes all it names, with items and with none", async () => {
	for (const extra of [[], [item("a_endpoint", "https://as.example/a")]]) {
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect((await takesUnused(composition(extra)))["discovery"]).toBeUndefined();
	}
});
