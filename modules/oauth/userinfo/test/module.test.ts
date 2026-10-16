import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { releasedClaims } from "@mod/oidc";
import { senderBinding } from "@mod/sender-binding";
import { sessions } from "@mod/session";
import { sessionTokens } from "@mod/session-tokens";
import { tokens } from "@mod/tokens";
import { afterEach, expect, it } from "vitest";
import userinfoModule from "../src/module.ts";

let stop = async () => {};
afterEach(async () => {
	failing = undefined;
	await stop();
});
/** How sessions fail: unable to tell answers 503; anything else is not userinfo's to answer. */
let failing: "unavailable" | "bug" | undefined;
const items = contract<readonly MetadataItem[]>("items");
/** The parts userinfo reads: every token is admitted, issued in a session no longer open. */
const parts = defineModule({ name: "parts" }, (m) => [
	m.provide(senderBinding).by(
		() =>
			({
				admitted: async () => ({
					kind: "admitted",
					access: {
						kind: "valid",
						id: "t",
						grant: { subject: "ann", scope: ["openid"] },
						tokenType: "Bearer",
					},
				}),
			}) as never,
	),
	m.provide(tokens).by(() => ({}) as never),
	m
		.provide(sessionTokens)
		.by(() => ({ sessionOf: async () => ({ kind: "bound", handle: "h" }) }) as never),
	m.provide(sessions).by(
		() =>
			({
				openContext: async () => {
					if (failing === "unavailable") throw new Unavailable("session");
					if (failing === "bug") throw new TypeError("bug");
					return undefined;
				},
			}) as never,
	),
	m.provide(releasedClaims).by(() => ({ of: async () => ({}) })),
	m.provide(items).by((c) => c.collect(metadata)),
]);

let logged = recordingLog();
async function serve() {
	logged = recordingLog();
	const app = await assemble({
		modules: [http, parts, userinfoModule],
		config: {
			// Many instances: userinfo keeps nothing, so it never refuses them.
			...kernelConfig({ deployment: "multi" }),
			...httpConfig({
				"public-origin": "https://as.example",
				"cors-origins": ["https://app.example"],
				"trusted-proxies": ["127.0.0.1"],
			}),
		},
		runtime: quietRuntime({ log: logged.log }),
	});
	await app.start();
	stop = () => app.stop(1000);
	const url = `http://127.0.0.1:${app.get(listening).port()}/oauth/userinfo`;
	return { app, url };
}

it("serves GET and POST, with or without a body, refusing a token whose session ended, never stored", async () => {
	const { url } = await serve();
	const sent = { authorization: "Bearer t", "x-forwarded-proto": "https" };
	const requests: [string, RequestInit][] = [
		["GET", { method: "GET", headers: sent }],
		["POST", { method: "POST", headers: sent }],
		["POST form", { method: "POST", headers: sent, body: new URLSearchParams({ a: "b" }) }],
		[
			"POST json",
			{ method: "POST", headers: { ...sent, "content-type": "application/json" }, body: "{}" },
		],
	];
	for (const [method, init] of requests) {
		const res = await fetch(url, init);
		expect([method, res.status, res.headers.get("cache-control"), await res.json()]).toEqual([
			method,
			401,
			"no-store",
			{ error: "invalid_token" },
		]);
	}
});

it("answers 503 when a check cannot tell, never stored, logging what failed", async () => {
	const { url } = await serve();
	failing = "unavailable";
	const res = await fetch(url, {
		headers: { authorization: "Bearer t", "x-forwarded-proto": "https" },
	});
	expect([res.status, res.headers.get("cache-control"), await res.json()]).toEqual([
		503,
		"no-store",
		{ error: "temporarily_unavailable" },
	]);
	expect(logged.lines().filter((l) => l.event === "userinfo.unavailable")).toEqual([
		{ level: "warn", event: "userinfo.unavailable", fields: { what: "session" } },
	]);
});

it("leaves an error that is not an inability to tell to http, neither 503 nor logged as unavailable", async () => {
	const { url } = await serve();
	failing = "bug";
	const res = await fetch(url, {
		headers: { authorization: "Bearer t", "x-forwarded-proto": "https" },
	});
	expect(res.status).toBe(500);
	expect(logged.lines().filter((l) => l.event === "userinfo.unavailable")).toEqual([]);
});

it("lets a listed origin's page send its token, its DPoP proof and a body's type, and read the challenge, the nonce and the wait", async () => {
	const { url } = await serve();
	const res = await fetch(url, {
		method: "OPTIONS",
		headers: {
			origin: "https://app.example",
			"access-control-request-method": "GET",
			"access-control-request-headers": "authorization, dpop, content-type",
			"x-forwarded-proto": "https",
		},
	});
	expect(res.headers.get("access-control-allow-origin")).toBe("https://app.example");
	const allowed = (res.headers.get("access-control-allow-headers") ?? "").toLowerCase();
	for (const name of ["authorization", "dpop", "content-type"]) expect(allowed).toContain(name);
	const got = await fetch(url, {
		headers: {
			origin: "https://app.example",
			authorization: "Bearer t",
			"x-forwarded-proto": "https",
		},
	});
	expect(got.headers.get("access-control-expose-headers")?.toLowerCase().split(/,\s*/)).toEqual(
		expect.arrayContaining(["www-authenticate", "dpop-nonce", "retry-after"]),
	);
});

it("names itself in the issuer's metadata", async () => {
	const { app } = await serve();
	expect(app.get(items)).toContainEqual({
		name: "userinfo_endpoint",
		value: "https://as.example/oauth/userinfo",
	});
});
