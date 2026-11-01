import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started, sceneOf } from "@mod/conformance";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ClientScene, oauthArea } from "../src/main.ts";

const issuer = "https://issuer.example";
const pair = generateKeyPairSync("ed25519");
/** The one origin whose pages may call the provider across origins. */
const page = "https://spa.example";
const stranger = "https://evil.example";
const svc: ClientScene = {
	id: "svc",
	kind: "confidential",
	method: "client_secret_post",
	secret: "svc-secret-0123456789abcdef",
	grants: ["client_credentials"],
	scopes: ["read"],
	defaultScopes: ["read"],
};
const credentials = { client_id: svc.id, client_secret: svc.secret ?? "" };
/** What the deployment's proxy adds to a call. */
const proxied = { "x-forwarded-proto": "https", "x-forwarded-for": "198.51.100.40" };
const form = { "content-type": "application/x-www-form-urlencoded" };

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(
		sceneOf(
			keysArea.part({
				signing: {
					kid: "co",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			}),
			// The origins are identity's part: it sets up the deployment's public face.
			identityArea.part({
				origin: issuer,
				users: [{ identifier: "alice", password: "correct horse battery", subject: "s-alice" }],
				corsOrigins: [page],
			}),
			oauthArea.part({ issuer, clients: [svc], revocation: true, discovery: true }),
		),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

/** A request to `path` from a page of `origin`. */
const from = (origin: string, path: string, init: RequestInit = {}) =>
	fetch(`${base}${path}`, {
		...init,
		headers: { ...proxied, origin, ...(init.headers as Record<string, string> | undefined) },
	});
/** A preflight from a page of `origin` for `method` on `path`, naming `headers` when given. */
const preflight = (origin: string, path: string, method: string, headers?: string) =>
	from(origin, path, {
		method: "OPTIONS",
		headers: {
			"access-control-request-method": method,
			...(headers ? { "access-control-request-headers": headers } : {}),
		},
	});
const listed = (res: Response, name: string) =>
	(res.headers.get(name) ?? "")
		.toLowerCase()
		.split(",")
		.map((s) => s.trim());
const issue = async () =>
	String(
		(
			(await (
				await fetch(`${base}/oauth/token`, {
					method: "POST",
					headers: { ...proxied, ...form },
					body: new URLSearchParams({ grant_type: "client_credentials", ...credentials }),
				})
			).json()) as { access_token?: string }
		).access_token,
	);

/** A preflight and a request from the listed origin are allowed; from any other, neither is. */
async function allowsOnlyTheListed(
	path: string,
	method: string,
	request: () => RequestInit,
	requestHeaders?: string,
) {
	const allowed = await preflight(page, path, method, requestHeaders);
	expect([allowed.ok, allowed.headers.get("access-control-allow-origin")]).toEqual([true, page]);
	expect(listed(allowed, "access-control-allow-methods")).toContain(method.toLowerCase());
	const answer = await from(page, path, request());
	expect(answer.status).toBe(200);
	expect(answer.headers.get("access-control-allow-origin")).toBe(page);
	expect(answer.headers.get("access-control-allow-credentials")).toBeNull();

	const refused = await preflight(stranger, path, method, requestHeaders);
	expect(refused.headers.get("access-control-allow-origin")).toBeNull();
	expect(refused.headers.get("access-control-allow-methods")).toBeNull();
	const other = await from(stranger, path, request());
	expect(other.headers.get("access-control-allow-origin")).toBeNull();
	expect(other.headers.get("access-control-expose-headers")).toBeNull();
	expect(listed(other, "vary")).toContain("origin");
	return { allowed, answer };
}

describe("cross-origin requests", () => {
	it("lets only a listed origin's page post a form and a DPoP proof to the token endpoint, and read the nonce, the challenge and the wait [oidc-discovery-3-aj]", async () => {
		const { allowed, answer } = await allowsOnlyTheListed(
			"/oauth/token",
			"POST",
			() => ({
				method: "POST",
				headers: form,
				body: new URLSearchParams({ grant_type: "client_credentials", ...credentials }),
			}),
			"content-type, dpop",
		);
		expect(listed(allowed, "access-control-allow-headers")).toEqual(
			expect.arrayContaining(["content-type", "dpop"]),
		);
		expect(listed(answer, "access-control-expose-headers")).toEqual(
			expect.arrayContaining(["dpop-nonce", "www-authenticate", "retry-after"]),
		);
	});

	it("lets only a listed origin's page revoke a token with a form [oidc-discovery-3-aj]", async () => {
		const tokens = [await issue(), await issue()];
		const { allowed } = await allowsOnlyTheListed(
			"/oauth/revoke",
			"POST",
			() => ({
				method: "POST",
				headers: form,
				body: new URLSearchParams({ token: tokens.shift() ?? "", ...credentials }),
			}),
			"content-type",
		);
		expect(listed(allowed, "access-control-allow-headers")).toContain("content-type");
	});

	it.each([
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/.well-known/jwks.json",
	])("lets only a listed origin's page read %s [oidc-discovery-3-aj]", async (path) => {
		await allowsOnlyTheListed(path, "GET", () => ({}));
	});
});
