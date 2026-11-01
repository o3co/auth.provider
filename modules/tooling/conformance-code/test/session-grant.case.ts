import { generateKeyPairSync } from "node:crypto";
import { areaTarget, faultyTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CodeScene, codeScene } from "../src/main.ts";
import { backChannel, browserAt } from "../src/testing.ts";

const issuer = "https://issuer.example";
/** How a session grant with no session to use is refused, by the target. */
const noSession = areaTarget().differs("session-grant-invalid-grant")
	? [401, "unauthorized"]
	: [400, "invalid_grant"];
const api = "https://api.example";
const pair = generateKeyPairSync("ed25519");
// Each client names its audience and an empty default scope, so both targets issue alike.
const bff: ClientScene = {
	id: "bff",
	kind: "confidential",
	method: "client_secret_basic",
	secret: "bff-secret-0123456789abcdef",
	grants: ["session"],
	scopes: ["read"],
	defaultScopes: [],
	audiences: [api],
};
const spa: ClientScene = {
	id: "spa",
	kind: "public",
	method: "none",
	grants: ["session"],
	scopes: ["read", "write"],
	defaultScopes: [],
	audiences: [api],
};
const svc: ClientScene = {
	id: "svc",
	kind: "confidential",
	method: "client_secret_basic",
	secret: "svc-secret-0123456789abcdef",
	// Allowed no grant, so not this one, and the scene needs no other grant composed.
	grants: [],
	scopes: ["read"],
	audiences: [api],
};
const bare: ClientScene = {
	id: "bare",
	kind: "confidential",
	method: "client_secret_basic",
	secret: "bare-secret-0123456789abcdef",
	grants: ["session"],
	scopes: ["read"],
	audiences: [api],
};
const fields: CodeScene = {
	issuer,
	keys: {
		signing: {
			kid: "sg",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [bff, spa, svc, bare],
	users: [{ identifier: "alice", password: "correct horse battery", subject: "user-alice" }],
	introspection: true,
	sessionGrant: true,
};
const scene = codeScene(fields);

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
const basic = (client: ClientScene) =>
	`Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`;

interface Asked {
	/** Sent with HTTP Basic; a public client names itself in the body instead. */
	readonly client?: ClientScene;
	readonly form?: Record<string, string>;
	/** The session cookie; the browser's own login when left out, none when empty. */
	readonly cookie?: string;
	/** The `Origin` header; the issuer when left out, none when null. */
	readonly origin?: string | null;
}

/** A session grant request from the browser's side, carrying its cookie. */
async function sessionGrant(asked: Asked = {}) {
	const cookie = asked.cookie ?? (await browser.login());
	const origin = asked.origin === undefined ? issuer : asked.origin;
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: browser.headers({
			"content-type": "application/x-www-form-urlencoded",
			...(cookie ? { cookie } : {}),
			...(origin === null ? {} : { origin }),
			...(asked.client ? { authorization: basic(asked.client) } : {}),
		}),
		body: new URLSearchParams({ grant_type: "session", ...asked.form }),
	});
	return { status: res.status, body: (await res.json()) as Record<string, string> };
}
const asBff = { client: bff, form: { scope: "read" } };
const asSpa = { form: { client_id: "spa", scope: "read" } };

async function introspect(token: string) {
	const res = await fetch(`${base}/oauth/introspect`, {
		method: "POST",
		headers: {
			...backChannel,
			"content-type": "application/x-www-form-urlencoded",
			authorization: basic(bff),
		},
		body: new URLSearchParams({ token }),
	});
	return (await res.json()) as Record<string, unknown>;
}

describe("session grant", () => {
	it("gives a confidential client an access token for the session's user, and nothing more [rfc6749-5.1-a]", async () => {
		const res = await sessionGrant(asBff);
		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({ token_type: "Bearer", scope: "read" });
		expect(res.body).not.toHaveProperty("refresh_token");
		expect(res.body).not.toHaveProperty("id_token");
		expect(await introspect(res.body.access_token ?? "")).toMatchObject({
			active: true,
			sub: "user-alice",
		});
	});

	it("gives a public client allowed the grant an access token too", async () => {
		const res = await sessionGrant(asSpa);
		expect(res.status).toBe(200);
		expect(await introspect(res.body.access_token ?? "")).toMatchObject({
			active: true,
			sub: "user-alice",
		});
	});

	it("carries the session's login in the token: how the user authenticated, and when", async () => {
		// A login of its own: the browser keeps an earlier test's session, signed in before this began.
		browser.forget();
		const before = Math.floor(Date.now() / 1000);
		const cookie = await browser.login();
		const after = Math.ceil(Date.now() / 1000);
		const res = await sessionGrant({ ...asBff, cookie });
		expect(res.status).toBe(200);
		const [, payload = ""] = (res.body.access_token ?? "").split(".");
		const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
		expect(claims.amr).toEqual(["pwd"]);
		expect(claims.auth_time).toBeGreaterThanOrEqual(before);
		expect(claims.auth_time).toBeLessThanOrEqual(after);
	});

	it("ends the token at logout, and issues nothing more on the same cookie", async () => {
		const cookie = await browser.login();
		const issued = await sessionGrant({ ...asBff, cookie });
		expect(issued.status).toBe(200);
		expect(await browser.logout()).toBe(200);
		expect((await introspect(issued.body.access_token ?? "")).active).toBe(false);
		const again = await sessionGrant({ ...asBff, cookie });
		expect([again.status, again.body.error]).toEqual(noSession);
	});
});

describe("session grant: refusals", () => {
	it("refuses a request without a session as invalid_grant [rfc6749-8.5-a]", async () => {
		const res = await sessionGrant({ ...asBff, cookie: "" });
		expect([res.status, res.body.error]).toEqual(noSession);
	});

	it("refuses a client not allowed the grant [rfc6749-5.2-a]", async () => {
		const res = await sessionGrant({ client: svc });
		expect([res.status, res.body.error]).toEqual([400, "unauthorized_client"]);
	});

	it.skipIf(areaTarget().differs("session-grant-same-origin-only"))(
		"refuses a request from another origin as unauthorized [guarantee-9-a]",
		async () => {
			const res = await sessionGrant({ ...asBff, origin: "https://elsewhere.example" });
			expect([res.status, res.body.error]).toEqual(noSession);
		},
	);

	it.skipIf(areaTarget().differs("session-grant-needs-origin-evidence"))(
		"refuses a request without same-origin evidence as unauthorized [guarantee-9-a]",
		async () => {
			const res = await sessionGrant({ ...asBff, origin: null });
			expect([res.status, res.body.error]).toEqual(noSession);
		},
	);

	it.skipIf(areaTarget().differs("session-grant-scope-left-out-without-defaults"))(
		"asks for a scope when the client has scopes and no default",
		async () => {
			const res = await sessionGrant({ client: bare });
			expect([res.status, res.body.error]).toEqual([400, "invalid_scope"]);
		},
	);
});

describe("session grant: whose allowance", () => {
	it("never issues outside the authenticated client's allowance for another client_id in the body", async () => {
		const res = await sessionGrant({ client: bff, form: { client_id: "spa", scope: "write" } });
		expect(res.status).not.toBe(200);
		expect(res.body).not.toHaveProperty("access_token");
	});

	it("refuses a confidential client named in the body without its credentials [rfc6749-2.2-a] [rfc6749-2.3.1-d] [rfc6749-3.2.1-a]", async () => {
		const res = await sessionGrant({ form: { client_id: "bff", scope: "read" } });
		expect([res.status, res.body.error]).toEqual([401, "invalid_client"]);
	});
});

describe.runIf(areaTarget().can("store-fault:session-grant"))(
	"session grant: the store failing",
	() => {
		const faulty = faultyTarget(scene);
		let at = "";
		beforeAll(() => {
			at = base;
			base = faulty.base();
			browser.forget();
		});
		afterAll(() => {
			base = at;
			browser.forget();
		});

		it("answers 503 while the store is unreachable, never an unauthorized session", async () => {
			const cookie = await browser.login();
			const answer = await faulty.whileDown(() => sessionGrant({ ...asBff, cookie }));
			expect([answer.status, answer.body.error]).toEqual([503, "temporarily_unavailable"]);
		});
	},
);
