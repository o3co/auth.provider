import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../../main.ts";
import { backChannel, browserAt, succeeded } from "../../testing.ts";

const issuer = "https://issuer.example";
const api = "https://api.example";
const callback = "https://app.example/cb";
const pair = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const user = { username: "alice", password: "correct horse battery" };
const secretOf = (id: string) => `${id}-secret-0123456789abcdef`;
/** A client of the code flow, for the API's audience or, with none, the issuer's. */
const coded = (id: string, audiences?: string[]): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: secretOf(id),
	grants: ["authorization_code"],
	scopes: ["openid"],
	redirectUris: [callback],
	firstParty: true,
	...(audiences ? { audiences } : {}),
});
/** A client that only introspects tokens for the audiences it is allowed. */
const reader = (id: string, audiences: string[]): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: secretOf(id),
	grants: [],
	scopes: [],
	audiences,
});

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(
		codeScene({
			issuer,
			keys: {
				signing: {
					kid: "aud",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [
				coded("app", [api]),
				coded("bare"),
				reader("resource", [api]),
				reader("watcher", [issuer]),
			],
			users: [{ identifier: user.username, password: user.password }],
			introspection: true,
			userinfo: true,
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

const form = async (path: string, body: Record<string, string>) => {
	const res = await fetch(`${base}${path}`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams(body),
	});
	return { status: res.status, body: (await res.json()) as Record<string, unknown> };
};
/** An access token the code flow issues `client` for openid. */
async function tokenOf(client: string) {
	const browser = browserAt(() => base, issuer, user);
	const answer = await browser.authorize({
		response_type: "code",
		client_id: client,
		redirect_uri: callback,
		state: "s1",
		scope: "openid",
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	const code = answer.at?.searchParams.get("code") ?? "";
	const issued = await succeeded(
		await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: callback,
				code_verifier: verifier,
				client_id: client,
				client_secret: secretOf(client),
			}),
		}),
		"the token endpoint",
	);
	return String(issued.access_token);
}
const payloadOf = (token: string) =>
	JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString());
const introspected = (token: string, by: string) =>
	form("/oauth/introspect", { token, client_id: by, client_secret: secretOf(by) });
const userinfo = async (token: string) =>
	(
		await fetch(`${base}/oauth/userinfo`, {
			headers: { ...backChannel, authorization: `Bearer ${token}` },
		})
	).status;
const listOf = (aud: unknown) => (Array.isArray(aud) ? aud : [aud]);

// The legacy build adds no audience, names a client with none by its id, and introspects otherwise.
describe.skipIf(areaTarget().differs("token-for-the-issuer"))(
	"an openid token for the issuer as well as its grant's audience",
	() => {
		it("names the issuer after the API in its aud, counted in aud_added, and is answered at userinfo [rfc9700-2.3-c]", async () => {
			const token = await tokenOf("app");
			expect(payloadOf(token)).toMatchObject({ aud: [api, issuer], aud_added: 1 });
			expect(await userinfo(token)).toBe(200);
		});

		it("is described by its grant's audience alone: a client allowed only the issuer sees it inactive", async () => {
			const token = await tokenOf("app");
			expect((await introspected(token, "watcher")).body).toEqual({ active: false });
			const described = await introspected(token, "resource");
			expect(described.body.active).toBe(true);
			expect(listOf(described.body.aud)).toEqual([api]);
		});

		it("keeps a token whose grant's audience is the issuer as it was: introspected for it, answered at userinfo [rfc9700-2.3-c]", async () => {
			const token = await tokenOf("bare");
			const payload = payloadOf(token);
			expect(listOf(payload.aud)).toEqual([issuer]);
			expect(payload.aud_added).toBeUndefined();
			const described = await introspected(token, "watcher");
			expect(described.body.active).toBe(true);
			expect(listOf(described.body.aud)).toEqual([issuer]);
			expect(await userinfo(token)).toBe(200);
		});
	},
);
