import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ClientScene, type OauthPart, oauthScene } from "../src/main.ts";

const pair = generateKeyPairSync("ed25519");
const keys = {
	signing: {
		kid: "md",
		alg: "EdDSA" as const,
		privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
		publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
	},
};
/** A client allowed `grants`, none unless given, so a scene needs no grant composed for it. */
const client = (
	id: string,
	method: ClientScene["method"],
	grants: readonly string[] = [],
): ClientScene => ({
	id,
	kind: method === "none" ? "public" : "confidential",
	method,
	...(method === "none" ? {} : { secret: `${id}-secret-0123456789abcdef` }),
	grants: [...grants],
	scopes: ["read"],
	defaultScopes: ["read"],
});

/** Runs a scene for the tests of a block; `get` reads a path of the running target. */
function running(issuer: string, more: Partial<OauthPart> = {}) {
	let started: Started;
	let base = "";
	beforeAll(async () => {
		started = await areaTarget().start(
			oauthScene({
				issuer,
				keys,
				clients: [
					client("basic", "client_secret_basic"),
					client("post", "client_secret_post"),
					client("pub", "none"),
				],
				introspection: true,
				revocation: true,
				discovery: true,
				...more,
			}),
		);
		if (started.kind !== "running") throw new Error(`refused:\n${started.output}`);
		base = started.baseUrl;
	});
	afterAll(async () => {
		if (started?.kind === "running") await started.stop();
	});
	return async (path: string) => {
		const res = await fetch(`${base}${path}`);
		const text = await res.text();
		return {
			status: res.status,
			body: (res.status === 200 ? JSON.parse(text) : {}) as Record<string, unknown>,
		};
	};
}

describe("the metadata document", () => {
	const issuer = "https://issuer.example";
	const get = running(issuer);

	it("is one document under both well-known names, naming the issuer first [oidc-discovery-4-a] [oidc-discovery-4.1-a] [oidc-discovery-4.3-a] [oidc-discovery-3-a] [rfc8414-2-a] [rfc8414-3-a] [rfc8414-3.1-a] [rfc8414-3.3-a] [rfc9700-2.6-a]", async () => {
		const openid = await get("/.well-known/openid-configuration");
		const oauth = await get("/.well-known/oauth-authorization-server");
		expect([openid.status, oauth.status]).toEqual([200, 200]);
		expect(oauth.body).toEqual(openid.body);
		expect(Object.keys(openid.body)[0]).toBe("issuer");
		expect(openid.body.issuer).toBe(issuer);
	});

	it("tells where the token, introspection and revocation endpoints are [rfc8414-2-c] [oidc-discovery-3-f]", async () => {
		const { body } = await get("/.well-known/openid-configuration");
		expect(body).toMatchObject({
			token_endpoint: `${issuer}/oauth/token`,
			introspection_endpoint: `${issuer}/oauth/introspect`,
			revocation_endpoint: `${issuer}/oauth/revoke`,
		});
	});

	it("lists the ways clients authenticate at the token endpoint", async () => {
		const { body } = await get("/.well-known/openid-configuration");
		expect(body.token_endpoint_auth_methods_supported).toEqual(
			expect.arrayContaining(["client_secret_basic", "client_secret_post", "none"]),
		);
	});
});

describe("the metadata document of a deployment with the client credentials grant", () => {
	const get = running("https://issuer.example", {
		clients: [client("svc", "client_secret_basic", ["client_credentials"])],
	});

	it("lists the grant", async () => {
		const { body } = await get("/.well-known/openid-configuration");
		expect(body.grant_types_supported).toContain("client_credentials");
	});
});

describe("the metadata document of a deployment without the JWT bearer grant", () => {
	const get = running("https://issuer.example", { jwtBearer: false });

	it("does not list a grant that is not set up, whether it lists others or, with none set up, leaves the member out", async () => {
		const { body } = await get("/.well-known/openid-configuration");
		// An empty list is left out of the document, so the member may be absent.
		expect((body.grant_types_supported as string[] | undefined) ?? []).not.toContain(
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
		);
	});
});

describe("the metadata document of an issuer with a path", () => {
	const issuer = "https://issuer.example/tenant";
	const get = running(issuer);

	it("is where RFC 8414 inserts the well-known name and where OpenID Connect appends it [rfc8414-3-a] [oidc-discovery-4-a] [rfc8414-3.3-a] [oidc-discovery-4.3-a]", async () => {
		for (const path of [
			"/.well-known/oauth-authorization-server/tenant",
			"/tenant/.well-known/openid-configuration",
		]) {
			const answer = await get(path);
			expect(answer.status).toBe(200);
			expect(answer.body.issuer).toBe(issuer);
		}
	});

	it.skipIf(areaTarget().differs("discovery-at-root-for-path-issuer"))(
		"is not at the root, where it would name another issuer",
		async () => {
			expect((await get("/.well-known/openid-configuration")).status).toBe(404);
			expect((await get("/.well-known/oauth-authorization-server")).status).toBe(404);
		},
	);
});
