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
const user = { username: "alice", password: "correct horse battery" };
const client = (id: string, scopes: string[]): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: `${id}-secret-0123456789abcdef`,
	grants: ["authorization_code"],
	scopes,
	redirectUris: [callback],
	firstParty: true,
});
const app = client("app", ["openid", "profile", "email"]);
/** A client not allowed the email scope. */
const narrow = client("narrow", ["openid", "profile"]);

let running: Started;
let base = "";
const browser = browserAt(() => base, issuer, user);
beforeAll(async () => {
	running = await areaTarget().start(
		codeScene({
			issuer,
			keys: {
				signing: {
					kid: "cl",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [app, narrow],
			users: [
				{ ...user, identifier: user.username, subject: "s-alice", email: "alice@example.com" },
			],
			discovery: true,
			userinfo: true,
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

/** The authorization response to a fresh login asking `scope` and `claims`, as `as`. */
async function asked(scope: string, claims: object, as: ClientScene = app) {
	browser.forget();
	return browser.authorize({
		response_type: "code",
		client_id: as.id,
		redirect_uri: callback,
		state: "s1",
		scope,
		claims: JSON.stringify(claims),
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
}
/** The ID token's claims and userinfo's answer for a code asking `scope` and `claims`. */
async function released(scope: string, claims: object, as: ClientScene = app) {
	const res = await asked(scope, claims, as);
	const exchanged = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "authorization_code",
			client_id: as.id,
			client_secret: as.secret ?? "",
			code: res.at?.searchParams.get("code") ?? "",
			redirect_uri: callback,
			code_verifier: verifier,
		}),
	});
	const tokens = (await succeeded(exchanged, "the token endpoint")) as Record<string, string>;
	const idToken = JSON.parse(
		Buffer.from((tokens.id_token ?? "").split(".")[1] ?? "", "base64url").toString(),
	) as Record<string, unknown>;
	const info = await fetch(`${base}/oauth/userinfo`, {
		headers: { ...backChannel, authorization: `Bearer ${tokens.access_token}` },
	});
	return { idToken, userinfo: (await succeeded(info, "userinfo")) as Record<string, unknown> };
}

describe.skipIf(areaTarget().differs("claims-names"))(
	"claims a request names beyond its scope",
	() => {
		it("releases a claim asked for userinfo beyond the scope, and one asked for the ID token there alone [oidc-core-5.5-a]", async () => {
			const toUserinfo = await released("openid", { userinfo: { email: { essential: true } } });
			expect(toUserinfo.userinfo).toEqual({ sub: "s-alice", email: "alice@example.com" });
			expect(toUserinfo.idToken).not.toHaveProperty("email");
			const toIdToken = await released("openid", { id_token: { email: null } });
			expect(toIdToken.idToken).toMatchObject({ email: "alice@example.com" });
			expect(toIdToken.userinfo).toEqual({ sub: "s-alice" });
		});

		it("releases no claim whose scope the client is not allowed, and refuses nothing for it [oidc-core-5.5.1-a]", async () => {
			const { userinfo } = await released(
				"openid",
				{ userinfo: { email: { essential: true } } },
				narrow,
			);
			expect(userinfo).toEqual({ sub: "s-alice" });
		});

		it("leaves out a claim, from the scope too, that a value it asks does not match", async () => {
			const other = await released("openid email", {
				userinfo: { email: { value: "bob@example.com" } },
			});
			expect(other.userinfo).not.toHaveProperty("email");
			// The ID token's own request asked nothing of it.
			expect(other.idToken).toMatchObject({ email: "alice@example.com" });
			const same = await released("openid", {
				userinfo: { email: { values: ["alice@example.com"] } },
			});
			expect(same.userinfo).toMatchObject({ email: "alice@example.com" });
		});

		it("issues a code only for the subject a sub value names [oidc-core-5.5.1-b] [oidc-core-3.1.2.2-d] [oidc-core-3.1.2.2-e]", async () => {
			const other = await asked("openid", { id_token: { sub: { value: "s-bob" } } });
			expect(other.at?.searchParams.get("error")).toBe("login_required");
			const same = await asked("openid", { id_token: { sub: { value: "s-alice" } } });
			expect(same.at?.searchParams.has("code")).toBe(true);
		});

		it("says in its metadata that it takes the claims parameter", async () => {
			const discovered = await fetch(`${base}/.well-known/openid-configuration`, {
				headers: backChannel,
			});
			expect((await succeeded(discovered, "discovery")).claims_parameter_supported).toBe(true);
		});
	},
);
