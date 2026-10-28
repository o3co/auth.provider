import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../../main.ts";
import { backChannel, browserAt, succeeded } from "../../testing.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const pair = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "app-secret-0123456789abcdef",
	grants: ["authorization_code"],
	scopes: ["openid", "read", "write"],
	redirectUris: [callback],
	firstParty: true,
	audiences: ["https://api.example"],
};

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(
		codeScene({
			issuer,
			keys: {
				signing: {
					kid: "sl",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [app],
			users: [{ identifier: "alice", password: "correct horse battery" }],
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

const browser = browserAt(() => base, issuer, {
	username: "alice",
	password: "correct horse battery",
});
const request = (extra: Record<string, string>) => ({
	response_type: "code",
	client_id: app.id,
	redirect_uri: callback,
	state: "s1",
	code_challenge: challenge,
	code_challenge_method: "S256",
	...extra,
});
const claimsOf = (jwt: string | undefined) =>
	JSON.parse(Buffer.from((jwt ?? "").split(".")[1] ?? "", "base64url").toString()) as Record<
		string,
		unknown
	>;

describe("space-delimited lists", () => {
	it("writes the scope it answers and the access token carries with one ASCII space between its values [oidc-core-14-d]", async () => {
		const res = await browser.authorize(request({ scope: "openid read write" }));
		const tokens = (await succeeded(
			await fetch(`${base}/oauth/token`, {
				method: "POST",
				headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "authorization_code",
					client_id: app.id,
					client_secret: app.secret ?? "",
					code: res.at?.searchParams.get("code") ?? "",
					redirect_uri: callback,
					code_verifier: verifier,
				}),
			}),
			"the token endpoint",
		)) as Record<string, string>;
		for (const [name, scope] of [
			["answer", tokens.scope],
			["access token", claimsOf(tokens.access_token).scope],
		] as const) {
			expect(scope, name).toMatch(/^[\x21-\x7E]+( [\x21-\x7E]+)*$/);
			expect(String(scope).split(" ").sort(), name).toEqual(["openid", "read", "write"]);
		}
	});

	it("splits a scope or prompt it reads on the ASCII space alone, a tab joining two values into none it knows [oidc-core-14-d]", async () => {
		const error = async (extra: Record<string, string>) =>
			(await browser.authorize(request(extra))).at?.searchParams.get("error");
		for (const scope of ["openid\tread", "openid\nread", "openid read"]) {
			expect(await error({ scope }), JSON.stringify(scope)).toBe("invalid_scope");
		}
		expect(await error({ scope: "openid read", prompt: "login\tconsent" })).toBe("invalid_request");
		expect(await error({ scope: "openid read" })).toBeNull();
	});
});
