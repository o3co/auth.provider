import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../../main.ts";
import { backChannel, succeeded } from "../../testing.ts";

// A token issued in no session comes from the client credentials grant: a scene of its own, so
// userinfo's other checks run where that grant is not composed.
const issuer = "https://issuer.example";
const pair = generateKeyPairSync("ed25519");
const svc: ClientScene = {
	id: "svc",
	kind: "confidential",
	method: "client_secret_post",
	secret: "svc-secret-0123456789abcdef",
	grants: ["client_credentials"],
	// userinfo serves only a token issued for openid.
	scopes: ["openid", "read"],
	defaultScopes: ["openid", "read"],
};

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(
		codeScene({
			issuer,
			keys: {
				signing: {
					kid: "un",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [svc],
			users: [],
			userinfo: true,
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

/** The token endpoint's answer to the client credentials grant for `scope`, if given. */
async function issued(scope?: string) {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "client_credentials",
			client_id: svc.id,
			client_secret: svc.secret ?? "",
			...(scope ? { scope } : {}),
		}),
	});
	return (
		((await succeeded(res, "the token endpoint")) as { access_token?: string }).access_token ?? ""
	);
}

describe("OpenID Connect userinfo: a token issued in no session", () => {
	it("answers only sub [oidc-core-5.3.2-d]", async () => {
		const res = await fetch(`${base}/oauth/userinfo`, {
			headers: { ...backChannel, authorization: `Bearer ${await issued()}` },
		});
		expect([res.status, Object.keys((await res.json()) as object)]).toEqual([200, ["sub"]]);
	});

	// This test's resource item reads "meant for it" as: the issuer's resource tells its own tokens by the openid scope (OIDC Core §5.3.1); see the userinfo card's Invariants.
	it.skipIf(areaTarget().differs("userinfo-needs-openid"))(
		"refuses a token whose scope lacks openid as insufficient scope (RFC 6750 §3.1) [rfc6749-7-a] [rfc6749-7.2-a] [rfc6750-3-a] [rfc6750-3-b] [rfc6750-3-c] [rfc6750-3-f] [rfc6750-3-g] [rfc6750-3.1-c] [rfc9700-2.3-c]",
		async () => {
			const res = await fetch(`${base}/oauth/userinfo`, {
				headers: { ...backChannel, authorization: `Bearer ${await issued("read")}` },
			});
			expect([
				res.status,
				res.headers.get("www-authenticate"),
				((await res.json()) as { error?: string }).error,
			]).toEqual([403, 'Bearer error="insufficient_scope"', "insufficient_scope"]);
		},
	);
});
