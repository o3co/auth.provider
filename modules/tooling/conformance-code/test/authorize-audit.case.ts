import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, auditEvents, type SentEvent, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../src/main.ts";
import { browserAt } from "../src/testing.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const pair = generateKeyPairSync("ed25519");
const challenge = createHash("sha256").update("v".repeat(43)).digest("base64url");
const client = (id: string, extra: Partial<ClientScene> = {}): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: `${id}-secret-0123456789abcdef`,
	grants: ["authorization_code"],
	scopes: ["openid", "read"],
	redirectUris: [callback],
	firstParty: true,
	...extra,
});
const defaults = { defaultScopes: ["read"] };
const scene = codeScene({
	issuer,
	keys: {
		signing: {
			kid: "aa",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		client("app", defaults),
		client("third", { ...defaults, firstParty: false }),
		// Allowed no grant, so not the code, and the scene needs no other grant composed.
		client("nocode", { ...defaults, grants: [] }),
		client("nodefault"),
	],
	users: [{ identifier: "alice", password: "correct horse battery" }],
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

const browser = browserAt(() => base, issuer, {
	username: "alice",
	password: "correct horse battery",
});
const request = (extra: Record<string, string> = {}) => ({
	response_type: "code",
	client_id: "app",
	redirect_uri: callback,
	state: "s1",
	scope: "openid",
	code_challenge: challenge,
	code_challenge_method: "S256",
	...extra,
});
const authorizing = (events: readonly SentEvent[]) =>
	events.filter((event) => event.kind.startsWith("authorize."));

describe.runIf(areaTarget().can(auditEvents.need))("authorization endpoint: audit events", () => {
	it("records a code given with the subject and the client, never the code [guarantee-8-c]", async () => {
		await browser.login();
		const given = await auditEvents.of(running).during(() => browser.authorize(request()));
		const code = given.result.at?.searchParams.get("code") ?? "";
		expect(code).not.toBe("");
		expect(authorizing(given.events)).toEqual([
			{
				kind: "authorize.granted",
				at: expect.any(Number),
				subject: expect.stringMatching(/./),
				attributes: { client: "app", response_type: "code", source: expect.any(String) },
			},
		]);
		expect(JSON.stringify(given.events)).not.toContain(code);
	});

	it("records the refusals decided for a client or its consent with their reason, and nothing for a malformed request", async () => {
		await browser.login();
		const trail = auditEvents.of(running);
		const refused = async (params: Record<string, string>) =>
			authorizing((await trail.during(() => browser.authorize(params))).events);
		const rejected = (client: string, reason: string) => [
			{
				kind: "authorize.rejected",
				at: expect.any(Number),
				attributes: { client, reason, source: expect.any(String) },
			},
		];
		expect(await refused(request({ client_id: "nocode" }))).toEqual(
			rejected("nocode", "grant_type_not_allowed"),
		);
		const { scope: _, ...unscoped } = request({ client_id: "nodefault" });
		expect(await refused(unscoped)).toEqual(rejected("nodefault", "scope_omitted_without_default"));
		expect(await refused(request({ client_id: "third", prompt: "none" }))).toEqual(
			rejected("third", "consent_required"),
		);
		expect(await refused(request({ code_challenge: "" }))).toEqual([]);
	});
});
