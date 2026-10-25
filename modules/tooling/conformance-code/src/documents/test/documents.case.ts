import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Fake, fakeHttp, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../../main.ts";
import { browserAt } from "../../testing.ts";

const issuer = "https://issuer.example";
const registeredId = "https://app.example/client.json";
const callback = "https://app.example/cb";
const pair = generateKeyPairSync("ed25519");
const challenge = createHash("sha256").update("d".repeat(43)).digest("base64url");
const user = { identifier: "alice", password: "correct horse battery" };
const scene = codeScene({
	issuer,
	keys: {
		signing: {
			kid: "cd",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		{
			id: registeredId,
			kind: "public",
			method: "none",
			grants: ["authorization_code"],
			scopes: ["openid"],
			defaultScopes: ["openid"],
			redirectUris: [callback],
			firstParty: true,
		},
	],
	users: [user],
	discovery: true,
	documents: { deny: ["denied.example"], scopes: ["openid"] },
});

let running: Started;
let base = "";
// Where a document would be fetched from, were any of the ids below fetched.
let documents: Fake;
beforeAll(async () => {
	documents = await fakeHttp(() => ({ status: 404 }));
	running = await areaTarget().start(scene);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
	await documents?.stop();
});

const browser = browserAt(() => base, issuer, {
	username: user.identifier,
	password: user.password,
});
const authorizing = (clientId: string, redirectUri: string) =>
	browser.authorize({
		response_type: "code",
		client_id: clientId,
		redirect_uri: redirectUri,
		state: "s1",
		scope: "openid",
		code_challenge: challenge,
		code_challenge_method: "S256",
	});

describe("metadata document clients: the metadata document", () => {
	it("says the provider takes client ids that are document URLs", async () => {
		const res = await fetch(`${base}/.well-known/openid-configuration`);
		const body = (await res.json()) as Record<string, unknown>;
		expect(body.client_id_metadata_document_supported).toBe(true);
	});
});

describe("metadata document clients: ids refused before any fetch", () => {
	// Each spelling either is no document URL or names a denied host, however it is written.
	const ids = () => {
		const port = new URL(documents.base).port;
		return [
			["plain http", `http://localhost:${port}/client`],
			["an IP literal", `https://127.0.0.1:${port}/client`],
			["localhost", `https://localhost:${port}/client`],
			["the root path", `https://localhost:${port}/`],
			["a query", "https://other.example/client?x=1"],
			["a fragment", "https://other.example/client#x"],
			["user information", "https://user@other.example/client"],
			["a dot segment", "https://other.example/a/../client"],
			["the default port", "https://other.example:443/client"],
			["a denied host", "https://denied.example/client"],
			["a denied host with a trailing dot", "https://denied.example./client"],
			["a denied host in upper case", "https://DENIED.example/client"],
		] as const;
	};

	it("answers each with 400 and no redirect, and fetches nothing", async () => {
		const answers = [];
		for (const [what, id] of ids()) {
			const res = await authorizing(id, "https://other.example/cb");
			answers.push({ what, status: res.status, redirected: res.at !== undefined });
		}
		expect(answers).toEqual(ids().map(([what]) => ({ what, status: 400, redirected: false })));
		expect(documents.received).toEqual([]);
	});
});

describe("metadata document clients: a registered client with a URL id", () => {
	it("is the registered client, its document never fetched in its place", async () => {
		const res = await authorizing(registeredId, callback);
		expect(`${res.at?.origin}${res.at?.pathname}`).toBe(callback);
		expect(res.at?.searchParams.has("code")).toBe(true);
		expect(res.at?.searchParams.get("state")).toBe("s1");
	});
});
