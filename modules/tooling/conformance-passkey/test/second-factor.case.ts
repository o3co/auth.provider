import { generateKeyPairSync } from "node:crypto";
import { type AreaScene, areaTarget, sceneOf } from "@mod/conformance";
import { codeScene } from "@mod/conformance-code";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { secondFactorArea } from "@mod/conformance-second-factor";
import {
	beginBinding,
	browser,
	issuer,
	password,
	running,
} from "@mod/conformance-second-factor/testing";
import {
	type Client,
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
	type Twist,
} from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { passkeyArea } from "../src/main.ts";

const pair = generateKeyPairSync("ed25519");
const at: Client = { origin: issuer };
const users = ["alice", "bob", "carol"];
const scene = sceneOf(
	keysArea.part({
		signing: {
			kid: "webauthn-mfa",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	}),
	identityArea.part({
		origin: issuer,
		users: users.map((identifier) => ({ identifier, password })),
		login: { attempts: 100, windowSeconds: 600 },
	}),
	secondFactorArea.part({ mode: "optional" }),
	passkeyArea.part({ rpId: new URL(issuer).hostname, origins: [issuer], secondFactor: true }),
);

type Browser = ReturnType<typeof browser>;
type Authenticator = ReturnType<typeof softwareAuthenticator>;

describe("WebAuthn as a second factor", () => {
	const s = running(scene);

	/** Signs `username` in and binds a credential of the authenticator as a second factor. */
	const enrol = async (username: string, authenticator: Authenticator) => {
		const b = browser(() => s.at.base);
		expect((await b.login(username)).status).toBe(200);
		const begun = await beginBinding(b, { kind: "webauthn" }, s.mail(), "json");
		const offered = begun.body as unknown as CreationOptions;
		const proof = authenticator.create(offered, at);
		const done = await b.send(
			"POST",
			"/session/mfa/enrollment/complete",
			{ transaction_id: String(begun.body.transaction), proof },
			{},
			"json",
		);
		return { offered, done };
	};
	/** A password login the factor holds, the factor's challenge answered by the authenticator. */
	const proved = async (username: string, authenticator: Authenticator, twist: Twist = {}) => {
		const b: Browser = browser(() => s.at.base);
		const held = await b.login(username);
		const transaction = String(held.body.transaction);
		const factor = (await b.factors(transaction)).find((f) => f.kind === "webauthn");
		const ids = { transaction_id: transaction, factor_id: factor?.id ?? "" };
		const asked = await b.send("POST", "/session/mfa/challenge", ids, {}, "json");
		const proof = authenticator.get(asked.body as unknown as RequestOptions, at, twist);
		return {
			held,
			asked,
			answer: await b.send("POST", "/session/mfa/verify", { ...ids, proof }, {}, "json"),
		};
	};

	it("binds a credential that need not be discoverable, and asks for it at the next login", async () => {
		const authenticator = softwareAuthenticator({ discoverable: false });
		const { offered, done } = await enrol("alice", authenticator);
		expect(offered.authenticatorSelection?.residentKey).toBe("discouraged");
		expect(done.status).toBe(200);
		const { held, asked, answer } = await proved("alice", authenticator);
		expect(held.body.transaction).toBeTruthy();
		expect(asked.status).toBe(200);
		expect((asked.body as { allowCredentials?: unknown[] }).allowCredentials).toHaveLength(1);
		expect(answer.status).toBe(200);
	});

	it("refuses an assertion whose count did not go up, and opens nothing", async () => {
		const authenticator = softwareAuthenticator();
		expect((await enrol("bob", authenticator)).done.status).toBe(200);
		expect((await proved("bob", authenticator)).answer.status).toBe(200);
		const { answer } = await proved("bob", authenticator, { counter: 0 });
		expect([answer.status, answer.body.error]).toEqual([401, "mfa_invalid"]);
	});

	it("refuses to bind a response to another challenge, binding nothing", async () => {
		const authenticator = softwareAuthenticator();
		const b = browser(() => s.at.base);
		expect((await b.login("carol")).status).toBe(200);
		const begun = await beginBinding(b, { kind: "webauthn" }, s.mail(), "json");
		const offered = begun.body as unknown as CreationOptions;
		const proof = authenticator.create({ ...offered, challenge: "AAAA" }, at);
		const done = await b.send(
			"POST",
			"/session/mfa/enrollment/complete",
			{ transaction_id: String(begun.body.transaction), proof },
			{},
			"json",
		);
		expect(done.status).toBe(401);
		expect((await b.send("GET", "/session/mfa/factors")).body.factors).toEqual([]);
	});
});

describe("acr asking the amr a passkey second factor proves", () => {
	/** An app with WebAuthn as its second factor, and an acr asking `amr` alone. */
	const asking = (amr: string): AreaScene => {
		const code = codeScene({
			issuer,
			keys: {
				signing: {
					kid: "webauthn-acr",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [],
			users: [{ identifier: "alice", password }],
			mfa: { mode: "optional" },
			acr: { values: { "urn:t:key": [[amr]] } },
		});
		const passkey = sceneOf(
			passkeyArea.part({ rpId: new URL(issuer).hostname, origins: [issuer], secondFactor: true }),
		);
		return { ...code, parts: { ...code.parts, ...passkey.parts } };
	};
	const started = async (scene: AreaScene) => {
		const run = await areaTarget().start(scene);
		if (run.kind === "running") await run.stop();
		return run;
	};

	it("starts with an acr asking pop, and refuses one asking hwk alone, which no passkey proves", async () => {
		expect((await started(asking("pop"))).kind).toBe("running");
		const hard = await started(asking("hwk"));
		// The legacy build's passkeys prove `hwk`.
		if (areaTarget().differs("passkey-amr-pop")) {
			expect(hard.kind).toBe("running");
			return;
		}
		expect(hard.kind).toBe("refused");
		if (hard.kind === "refused") expect(hard.output).toMatch(/acr\.values\.urn:t:key/);
	});
});
