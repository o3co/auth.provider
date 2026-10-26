import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { exchangeScene } from "../src/main.ts";

const issuer = "https://issuer.example";
const [api, admin] = ["https://api.example", "https://admin.example"];
const exchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
const accessType = "urn:ietf:params:oauth:token-type:access_token";
const signing = generateKeyPairSync("ed25519");
const secret = "gateway-secret-0123456789abcdef";
const scene = (resourceIndicators: boolean) =>
	exchangeScene({
		issuer,
		keys: {
			signing: {
				kid: "te",
				alg: "EdDSA",
				privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		clients: [
			{
				id: "gateway",
				kind: "confidential",
				method: "client_secret_post",
				secret,
				grants: ["client_credentials", exchangeGrant],
				scopes: ["read"],
				defaultScopes: ["read"],
				audiences: [api, admin],
			},
		],
		users: [{ identifier: "alice", password: "correct horse battery" }],
		...(resourceIndicators ? { resourceIndicators: true } : {}),
		// The subject is the client's own token, which names no user: verified-email refuses it.
		without: ["@mod/verified-email"],
	});

/** What the deployment's proxy adds to a client's own call. */
const backChannel = {
	"x-forwarded-proto": "https",
	"x-forwarded-for": "198.51.100.21",
	"x-forwarded-host": new URL(issuer).host,
};

/** A token request by the client, answered as its status, error and the issued token's audience. */
async function token(base: string, fields: Record<string, string>) {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ ...fields, client_id: "gateway", client_secret: secret }),
	});
	const body = (await res.json()) as Record<string, unknown>;
	const claims =
		typeof body.access_token === "string"
			? JSON.parse(Buffer.from(body.access_token.split(".")[1] ?? "", "base64url").toString())
			: {};
	return {
		status: res.status,
		error: body.error,
		aud: claims.aud === undefined ? undefined : [claims.aud].flat(),
		token: typeof body.access_token === "string" ? body.access_token : "",
	};
}

/** What an exchange answers for a resource, the subject token the client's own. */
async function exchanged(base: string, resource: string) {
	const own = await token(base, { grant_type: "client_credentials" });
	const { token: _, ...answer } = await token(base, {
		grant_type: exchangeGrant,
		subject_token: own.token,
		subject_token_type: accessType,
		resource,
	});
	return answer;
}

describe("RFC 8707: token exchange answers the same, the rule composed or not", () => {
	const started: Started[] = [];
	beforeAll(async () => {
		for (const on of [true, false]) {
			const s = await areaTarget().start(scene(on));
			if (s.kind !== "running") throw new Error(`refused:\n${s.output}`);
			started.push(s);
		}
	});
	afterAll(async () => {
		for (const s of started) if (s.kind === "running") await s.stop();
	});
	const bases = () => started.map((s) => (s.kind === "running" ? s.baseUrl : ""));

	it("narrows to a resource within the subject token's audience, and refuses one outside it [rfc8707-2-c] [rfc8693-2.2.2-a] [rfc8693-2.2.2-c] [rfc6749-5.2-a]", async () => {
		for (const base of bases()) {
			const own = await token(base, { grant_type: "client_credentials" });
			const held = own.aud ?? [];
			const outside = [api, admin].find((a) => !held.includes(a)) ?? "";
			expect(await exchanged(base, held[0] ?? "")).toMatchObject({ status: 200, aud: [held[0]] });
			expect(await exchanged(base, outside)).toMatchObject({
				status: 400,
				error: "invalid_target",
			});
		}
	});
});
