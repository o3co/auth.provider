import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { areaTarget, auditEvents, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ClientScene, oauthScene } from "../src/main.ts";

const issuer = "https://issuer.example";
/** A bcrypt hash (cost 4) of `bcryptSecret`, as an operator's tool writes one. */
const bcryptSecret = "bcrypt-secret-0123456789abcdef";
const bcryptHash = "$2b$04$xms06XNkMZ9nbe.PP0WG1e1tn4yBk5f9AOGEJwLlSyngB6N6mCam.";
const pair = generateKeyPairSync("ed25519");
const confidential = (
	id: string,
	method: ClientScene["method"],
	extra: Partial<ClientScene> = {},
): ClientScene => ({
	id,
	kind: "confidential",
	method,
	secret: `${id}-secret-0123456789abcdef`,
	grants: ["client_credentials"],
	scopes: ["read", "write"],
	defaultScopes: ["read"],
	...extra,
});
const withoutDefaults = ({ defaultScopes: _, ...rest }: ClientScene): ClientScene => rest;
const scene = oauthScene({
	issuer,
	keys: {
		signing: {
			kid: "cc",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		confidential("basic", "client_secret_basic", {
			audiences: ["https://api.example", "https://other.example"],
		}),
		confidential("post", "client_secret_post"),
		// Allowed no grant: one nothing composed serves would refuse boot.
		confidential("nogrant", "client_secret_basic", { grants: [] }),
		withoutDefaults(confidential("nodefault", "client_secret_basic")),
		confidential("emptydefault", "client_secret_basic", { defaultScopes: [] }),
		{ id: "pub", kind: "public", method: "none", grants: ["client_credentials"], scopes: ["read"] },
		...(["client_secret_basic", "client_secret_post"] as const).map((method) => {
			const { secret: _, ...rest } = confidential(`bcrypt-${method}`, method);
			return { ...rest, secretHash: bcryptHash };
		}),
	],
});

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(scene);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

async function token(form: Record<string, string>, basic?: [string, string]) {
	const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
	if (basic)
		headers.authorization = `Basic ${Buffer.from(`${basic[0]}:${basic[1]}`).toString("base64")}`;
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers,
		body: new URLSearchParams(form),
	});
	return {
		status: res.status,
		headers: res.headers,
		body: (await res.json()) as Record<string, unknown>,
	};
}
const secretOf = (id: string) => `${id}-secret-0123456789abcdef`;
const cc = { grant_type: "client_credentials" };

function decode(jwt: string): { header: Record<string, unknown>; claims: Record<string, unknown> } {
	const [h, c] = jwt.split(".");
	return {
		header: JSON.parse(Buffer.from(h ?? "", "base64url").toString()),
		claims: JSON.parse(Buffer.from(c ?? "", "base64url").toString()),
	};
}

describe("C. client credentials", () => {
	it("issues a signed access token to a client authenticated with basic [rfc6749-5.1-a] [rfc6749-5.1-b] [rfc6749-2.3.1-a] [oidc-core-10.1-c]", async () => {
		const res = await token({ ...cc, scope: "read write" }, ["basic", secretOf("basic")]);
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control")).toContain("no-store");
		expect(res.body).toMatchObject({ token_type: "Bearer", scope: "read write" });
		expect(res.body.expires_in).toBeGreaterThan(0);
		const jwt = String(res.body.access_token);
		const { header, claims } = decode(jwt);
		expect(header.typ).toBe("at+jwt");
		expect(claims).toMatchObject({
			iss: issuer,
			sub: "basic",
			client_id: "basic",
			aud: "https://api.example",
		});
		const { keys } = (await (await fetch(`${base}/.well-known/jwks.json`)).json()) as {
			keys: Record<string, unknown>[];
		};
		const jwk = keys.find((k) => k.kid === header.kid);
		expect(jwk).toBeDefined();
		const [h, c, s] = jwt.split(".");
		const key = createPublicKey({ key: jwk as never, format: "jwk" });
		expect(verify(null, Buffer.from(`${h}.${c}`), key, Buffer.from(s ?? "", "base64url"))).toBe(
			true,
		);
	});

	it("issues to a client authenticated with post and grants the default scopes when none is asked [rfc6749-3.3-a] [rfc6749-3.3-b]", async () => {
		const res = await token({ ...cc, client_id: "post", client_secret: secretOf("post") });
		expect(res.status).toBe(200);
		expect(res.body.scope).toBe("read");
	});

	it("refuses wrong, unknown and missing client credentials with invalid_client [rfc6749-5.2-b] [rfc6749-3.2.1-a] [rfc6749-4.4.2-a]", async () => {
		const wrong = await token(cc, ["basic", "nope"]);
		expect([wrong.status, wrong.body.error]).toEqual([401, "invalid_client"]);
		expect(wrong.headers.get("www-authenticate")).toMatch(/^Basic/);
		const wrongPost = await token({ ...cc, client_id: "post", client_secret: "nope" });
		expect([wrongPost.status, wrongPost.body.error]).toEqual([401, "invalid_client"]);
		const unknown = await token(cc, ["ghost", "x"]);
		expect([unknown.status, unknown.body.error]).toEqual([401, "invalid_client"]);
		const none = await token(cc);
		expect([none.status, none.body.error]).toEqual([401, "invalid_client"]);
	});

	it("refuses a client whose allowed grants do not name client_credentials", async () => {
		const res = await token(cc, ["nogrant", secretOf("nogrant")]);
		expect([res.status, res.body.error]).toEqual([400, "unauthorized_client"]);
	});

	it("refuses scopes outside the client's allowance and a missing scope without defaults [rfc6749-3.3-b]", async () => {
		const outside = await token({ ...cc, scope: "admin" }, ["basic", secretOf("basic")]);
		expect([outside.status, outside.body.error]).toEqual([400, "invalid_scope"]);
		const missing = await token(cc, ["nodefault", secretOf("nodefault")]);
		expect([missing.status, missing.body.error]).toEqual([400, "invalid_scope"]);
	});

	it("refuses an unsupported, missing or repeated grant_type [rfc6749-5.2-a] [rfc6749-5.2-f] [rfc6749-3.2-d]", async () => {
		const auth: [string, string] = ["basic", secretOf("basic")];
		const unsupported = await token({ grant_type: "urn:example:nothing" }, auth);
		expect([unsupported.status, unsupported.body.error]).toEqual([400, "unsupported_grant_type"]);
		const missing = await token({}, auth);
		expect([missing.status, missing.body.error]).toEqual([400, "invalid_request"]);
		const repeated = await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				authorization: `Basic ${Buffer.from(`basic:${secretOf("basic")}`).toString("base64")}`,
			},
			body: "grant_type=client_credentials&grant_type=client_credentials",
		});
		expect(repeated.status).toBe(400);
		expect(((await repeated.json()) as Record<string, unknown>).error).toBe("invalid_request");
	});
});

describe("C. client credentials: a secret kept as a bcrypt hash", () => {
	it("authenticates the client by basic and by post, and refuses a wrong secret [rfc6749-2.3.1-a] [rfc6749-3.2.1-a]", async () => {
		const basic = "bcrypt-client_secret_basic";
		const post = "bcrypt-client_secret_post";
		const byBasic = await token(cc, [basic, bcryptSecret]);
		expect([byBasic.status, byBasic.body.token_type]).toEqual([200, "Bearer"]);
		const byPost = await token({ ...cc, client_id: post, client_secret: bcryptSecret });
		expect([byPost.status, byPost.body.token_type]).toEqual([200, "Bearer"]);
		const wrong = await token(cc, [basic, secretOf(basic)]);
		expect([wrong.status, wrong.body.error]).toEqual([401, "invalid_client"]);
		const wrongPost = await token({ ...cc, client_id: post, client_secret: secretOf(post) });
		expect([wrongPost.status, wrongPost.body.error]).toEqual([401, "invalid_client"]);
	});
});

describe.runIf(areaTarget().can(auditEvents.need))("C. client credentials: audit events", () => {
	it("records an issuance and a refused grant with the client and the grant type, and a refused client by its reason alone, never the token or secret", async () => {
		const trail = auditEvents.of(running);
		const issued = await trail.during(() => token(cc, ["basic", secretOf("basic")]));
		const refused = await trail.during(() => token(cc, ["nogrant", secretOf("nogrant")]));
		const unknown = await trail.during(() => token(cc, ["basic", "nope"]));
		expect([issued.result.status, refused.result.status, unknown.result.status]).toEqual([
			200, 400, 401,
		]);
		const by = (client: string) => ({ client, source: expect.any(String), ...cc });
		expect(issued.events).toEqual([
			{ kind: "token.issued", at: expect.any(Number), attributes: by("basic") },
		]);
		expect(refused.events).toEqual([
			{
				kind: "token.issued.failure",
				at: expect.any(Number),
				attributes: {
					...by("nogrant"),
					reason: "grant_type_not_allowed",
					error: "unauthorized_client",
				},
			},
		]);
		// Before any client is known: the reason and the source, never the client id claimed.
		expect(unknown.events).toEqual(
			areaTarget().differs("client-authentication-failure-recorded")
				? []
				: [
						{
							kind: "client.authentication.failure",
							at: expect.any(Number),
							attributes: { source: expect.any(String), reason: "bad_credentials" },
						},
					],
		);
		const sent = JSON.stringify([issued.events, refused.events, unknown.events]);
		expect(sent).not.toContain(String(issued.result.body.access_token));
		expect(sent).not.toMatch(/secret/);
	});
});

describe("C. client credentials: defaults", () => {
	it("grants a repeated scope once", async () => {
		const res = await token({ ...cc, scope: "read read" }, ["basic", secretOf("basic")]);
		expect(res.body.scope).toBe("read");
	});

	it("issues no scope for an explicitly empty default and refuses when no default is set [rfc6749-3.3-b]", async () => {
		const empty = await token(cc, ["emptydefault", secretOf("emptydefault")]);
		expect([empty.status, empty.body.scope]).toEqual([200, undefined]);
		const unset = await token(cc, ["nodefault", secretOf("nodefault")]);
		expect([unset.status, unset.body.error]).toEqual([400, "invalid_scope"]);
	});
});

describe("C. client credentials: answers the owner decided", () => {
	const driver = areaTarget();

	it.skipIf(driver.differs("public-client-for-client-credentials"))(
		"refuses a public client as unauthorized [rfc6749-4.4-a]",
		async () => {
			const res = await token({ ...cc, client_id: "pub" });
			expect([res.status, res.body.error]).toEqual([400, "unauthorized_client"]);
		},
	);

	it.skipIf(driver.differs("two-client-auth-methods"))(
		"refuses credentials sent with two methods at once [rfc6749-2.3-b]",
		async () => {
			const res = await token({ ...cc, client_id: "basic", client_secret: secretOf("basic") }, [
				"basic",
				secretOf("basic"),
			]);
			expect([res.status, res.body.error]).toEqual([400, "invalid_request"]);
		},
	);

	it.skipIf(driver.differs("get-on-token-endpoint"))(
		"answers GET on the token endpoint with 405",
		async () => {
			expect((await fetch(`${base}/oauth/token`)).status).toBe(405);
		},
	);

	it.skipIf(driver.differs("non-form-token-request"))("reads only form bodies", async () => {
		const res = await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				authorization: `Basic ${Buffer.from(`basic:${secretOf("basic")}`).toString("base64")}`,
			},
			body: JSON.stringify(cc),
		});
		expect(res.status).toBe(400);
	});
});
