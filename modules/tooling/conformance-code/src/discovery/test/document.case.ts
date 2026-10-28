import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, expect, it } from "vitest";
import { codeScene } from "../../main.ts";

const issuer = "https://issuer.example";
const pair = generateKeyPairSync("ed25519");

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(
		codeScene({
			issuer,
			keys: {
				signing: {
					kid: "md",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [
				{
					id: "app",
					kind: "confidential",
					method: "client_secret_post",
					secret: "app-secret-0123456789abcdef",
					grants: ["authorization_code"],
					scopes: ["openid"],
					defaultScopes: ["openid"],
					redirectUris: ["https://app.example/cb"],
					firstParty: true,
				},
			],
			users: [{ identifier: "alice", password: "correct horse battery" }],
			introspection: true,
			revocation: true,
			discovery: true,
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

/** OpenID Connect Discovery §3's members an OpenID Provider must publish. */
const required = [
	"issuer",
	"authorization_endpoint",
	"token_endpoint",
	"jwks_uri",
	"response_types_supported",
	"subject_types_supported",
	"id_token_signing_alg_values_supported",
];

it("is one JSON object of OpenID Connect Discovery's form: its required members, each value of its type, none empty [oidc-discovery-4-b]", async () => {
	const res = await fetch(`${base}/.well-known/openid-configuration`);
	expect(res.status).toBe(200);
	expect(res.headers.get("content-type")).toMatch(/^application\/json(;|$)/);
	const body: unknown = await res.json();
	expect(typeof body === "object" && body !== null && !Array.isArray(body)).toBe(true);
	const document = body as Record<string, unknown>;
	for (const member of required) expect(document, member).toHaveProperty(member);
	for (const [member, value] of Object.entries(document)) {
		if (member === "issuer" || /_(endpoint|uri)$/.test(member)) {
			// A location: an absolute https URL, with no query or fragment where it is the issuer.
			expect(typeof value, member).toBe("string");
			expect(new URL(value as string).protocol, member).toBe("https:");
		} else if (member.endsWith("_supported") && typeof value !== "boolean") {
			// A list of the values taken: never empty, each a string, each once.
			expect(Array.isArray(value), member).toBe(true);
			const list = value as unknown[];
			expect(list.length, member).toBeGreaterThan(0);
			expect(
				list.every((each) => typeof each === "string" && each !== ""),
				member,
			).toBe(true);
			expect(new Set(list).size, member).toBe(list.length);
		} else {
			expect(["string", "boolean"], member).toContain(typeof value);
		}
		expect(value, member).not.toEqual("");
	}
	expect(document.issuer).toBe(issuer);
});
