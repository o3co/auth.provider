import { claimsSelections } from "@mod/claims-selection";
import { listening, site } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { issuer, type MetadataItem, metadata } from "@mod/issuer";
import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import { type ReleasedClaims, releasedClaims } from "@mod/oidc";
import { senderBinding } from "@mod/sender-binding";
import { sessions } from "@mod/session";
import { stubSessions } from "@mod/session/testing";
import { sessionTokens } from "@mod/session-tokens";
import { type AudienceAddition, audienceAdditions, tokens } from "@mod/tokens";
import { afterEach, expect, it } from "vitest";
import userinfoModule from "../src/module.ts";

let stop = async () => {};
afterEach(async () => {
	failing = undefined;
	issuerUrl = "https://as.example";
	await stop();
});
/** The issuer this provider is named by. */
let issuerUrl = "https://as.example";
/** How sessions fail: unable to tell answers 503; anything else is not userinfo's to answer. */
let failing: "unavailable" | "bug" | undefined;
const items = contract<readonly MetadataItem[]>("items");
const additions = contract<readonly AudienceAddition[]>("additions");
/** The parts userinfo reads: every token is admitted, issued in a session no longer open. */
const parts = defineModule({ name: "parts", takes: [metadata, audienceAdditions] }, (m) => [
	m.provide(senderBinding).by(
		() =>
			({
				admitted: async () => ({
					kind: "admitted",
					access: {
						kind: "valid",
						id: "t",
						grant: { subject: "ann", audience: ["app"], scope: ["openid"] },
						addedAudience: [issuerUrl],
						tokenType: "Bearer",
					},
				}),
			}) as never,
	),
	m.provide(tokens).by(() => ({}) as never),
	m
		.provide(sessionTokens)
		.by(() => ({ sessionOf: async () => ({ kind: "bound", handle: "h" }) }) as never),
	m.provide(sessions).by(() =>
		stubSessions({
			entryOf: async () => {
				if (failing === "unavailable") throw new Unavailable("session");
				if (failing === "bug") throw new TypeError("bug");
				return { kind: "absent" };
			},
		}),
	),
	m
		.provide(releasedClaims)
		.by(() => ({ of: async () => ({}), scopeOf: () => undefined }) as ReleasedClaims),
	m.provide(claimsSelections).by(() => ({ forToken: async () => undefined }) as never),
	m.provide(items).by((c) => c.collect(metadata)),
	m.provide(additions).by((c) => c.collect(audienceAdditions)),
	m.provide(issuer).by(() => ({ url: issuerUrl })),
]);

let logged = recordingLog();
async function serve(publicOrigin: string | null = "https://as.example") {
	logged = recordingLog();
	const app = await assemble(composition(publicOrigin));
	await app.start();
	stop = () => app.stop(1000);
	const url = `http://127.0.0.1:${app.get(listening).port()}/oauth/userinfo`;
	return { app, url };
}

/** userinfo beside http and the parts it reads, on many instances, reached at `publicOrigin`; null writes none. */
function composition(publicOrigin: string | null = "https://as.example") {
	return {
		modules: [http, parts, userinfoModule],
		config: {
			// Many instances: userinfo keeps nothing, so it never refuses them.
			...kernelConfig({ deployment: "multi" }),
			...httpConfig({
				...(publicOrigin ? { "public-origin": publicOrigin } : {}),
				"cors-origins": ["https://app.example"],
				"trusted-proxies": ["127.0.0.1"],
			}),
		},
		runtime: quietRuntime({ log: logged.log }),
	};
}

it("serves GET and POST, with or without a body, refusing a token whose session ended, never stored [oidc-core-5.3-a] [rfc6750-3.1-b]", async () => {
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

it("lets a listed origin's page send its token, its DPoP proof and a body's type, and read the challenge, the nonce and the wait [oidc-core-5.3-c]", async () => {
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

it("adds the issuer to the audience of a token issued for openid, and to none other [rfc9700-2.3-c]", async () => {
	const { app } = await serve();
	const [addition] = app.get(additions);
	const grant = { subject: "ann", issuedTo: "app", audience: ["https://api.example"] };
	expect(addition?.added({ ...grant, scope: ["openid", "profile"] })).toEqual([issuerUrl]);
	expect(addition?.added({ ...grant, scope: ["read"] })).toEqual([]);
});

it("names itself in the issuer's metadata [oidc-discovery-3-h]", async () => {
	const { app } = await serve();
	expect(app.get(items)).toContainEqual({
		name: "userinfo_endpoint",
		value: "https://as.example/oauth/userinfo",
	});
});

it("names itself on the issuer's origin where no public origin is written [oidc-discovery-3-h]", async () => {
	issuerUrl = "https://login.example/tenant";
	const { app } = await serve(null);
	expect(app.get(site).origin).toBeUndefined();
	expect(app.get(items)).toContainEqual({
		name: "userinfo_endpoint",
		value: "https://login.example/oauth/userinfo",
	});
});

it("takes all it names", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(composition()))["userinfo"]).toBeUndefined();
});
