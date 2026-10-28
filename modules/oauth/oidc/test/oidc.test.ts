import { randomBytes } from "node:crypto";
import { claimsSelections } from "@mod/claims-selection";
import { claimsSelectionConfig } from "@mod/claims-selection/testing";
import type { IdTokenRequest } from "@mod/code-grant";
import type { Assembly } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import { userAttribute } from "@mod/users";
import usersModule from "@mod/users/module";
import { testUser, usersConfig } from "@mod/users/testing";
import { describe, expect, it } from "vitest";
import oidc from "../src/module.ts";
import {
	booted,
	composed,
	hooks,
	loginOf,
	makers,
	published,
	sessionsOf,
	unanswering,
} from "./parts.ts";

const now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });

/** A request as code-grant makes it for an openid code; `more` changes what a case is about. */
const request = (more: Partial<IdTokenRequest> = {}): IdTokenRequest => ({
	subject: "a",
	clientId: "c",
	authenticatedAt: now,
	amr: [],
	scope: ["openid"],
	session: "s",
	redemption: "r-test",
	...more,
});

/** A compact JWS's header and payload, read without checking the signature. */
const decoded = (token: string) => {
	const [header, payload] = token
		.split(".")
		.slice(0, 2)
		.map((part) => JSON.parse(Buffer.from(part, "base64url").toString()));
	return { header, payload };
};

const makerOf = (app: Assembly) => {
	const [maker] = app.get(makers);
	if (!maker) throw new Error("no maker");
	return maker;
};

describe("the ID token", () => {
	it("is signed with the core claims and the session [oidc-core-2-a] [oidc-core-2-b] [oidc-core-2-d] [oidc-core-2-e] [oidc-core-2-f] [oidc-core-2-g] [oidc-core-2-i] [oidc-core-2-n] [oidc-core-2-o] [oidc-core-15.1-e] [oidc-core-7.4-b]", async () => {
		const app = await booted({ runtime, config: { oidc: { "id-token-lifetime": "5m" } } });
		const token = await makerOf(app).make(
			request({
				subject: "alice",
				clientId: "app",
				nonce: "n1",
				authenticatedAt: now - 5000,
				amr: ["pwd"],
				acr: "urn:x",
				session: "s1",
			}),
		);
		expect(decoded(token).payload).toEqual({
			iss: "https://as.example",
			sub: "alice",
			aud: "app",
			azp: "app",
			iat: now / 1000,
			exp: now / 1000 + 300,
			auth_time: (now - 5000) / 1000,
			amr: ["pwd"],
			acr: "urn:x",
			nonce: "n1",
			sid: "s1",
		});
		expect((await app.get(keys).verify(token, "JWT")).kind).toBe("valid");
	});

	it("carries the nonce and acr only when the request had them", async () => {
		const { payload } = decoded(await makerOf(await booted({ runtime })).make(request()));
		expect(payload).not.toHaveProperty("nonce");
		expect(payload).not.toHaveProperty("acr");
	});

	it("lasts an hour unless the section says otherwise", async () => {
		const { payload } = decoded(await makerOf(await booted({ runtime })).make(request()));
		expect(payload.exp - payload.iat).toBe(3600);
	});

	it("dates iat and auth_time in whole seconds, rounded down", async () => {
		const late = now + 999;
		const app = await booted({ runtime: quietRuntime({ clock: { now: () => late } }) });
		const { payload } = decoded(await makerOf(app).make(request({ authenticatedAt: late - 5500 })));
		expect([payload.iat, payload.auth_time]).toEqual([now / 1000, now / 1000 - 5]);
	});

	it("is made for the openid scope", async () => {
		expect(makerOf(await booted({ runtime })).scope).toBe("openid");
	});

	it("never dates auth_time after iat", async () => {
		const maker = makerOf(await booted({ runtime }));
		const { payload } = decoded(await maker.make(request({ authenticatedAt: now + 30_000 })));
		expect(payload.auth_time).toBe(payload.iat);
	});

	it("carries no auth_time when the authentication time is unknown", async () => {
		const maker = makerOf(await booted({ runtime }));
		const unknown = request({ authenticatedAt: now - 5000, authenticatedAtUnknown: true });
		const { payload } = decoded(await maker.make(unknown));
		expect(payload).not.toHaveProperty("auth_time");
		expect(payload).toMatchObject({ sub: "a", iat: now / 1000, sid: "s" });
		const known = decoded(await maker.make(request({ authenticatedAt: now - 5000 })));
		expect(known.payload.auth_time).toBe((now - 5000) / 1000);
	});

	it("names the JWT type, the algorithm keys signs with, and its key id in the header, and nothing else [oidc-core-10.1-d] [oidc-core-2-r]", async () => {
		const { header } = decoded(await makerOf(await booted({ runtime })).make(request()));
		expect([header.typ, header.alg, typeof header.kid]).toEqual(["JWT", "EdDSA", "string"]);
		// No x5u, x5c, jku or jwk: the key is found by its kid in the published set alone.
		expect(Object.keys(header).sort()).toEqual(["alg", "kid", "typ"]);
	});
});

it("refuses to start with a shared-secret signing key", async () => {
	const secret = randomBytes(32).toString("base64");
	const shared = { keys: { signing: { kid: "h", alg: "HS256", secret } } };
	await expect(booted({ runtime, config: shared })).rejects.toMatchObject({
		refusals: [{ where: "oidc", reason: "ID tokens need an asymmetric signing key" }],
	});
});

it("takes a lifetime of whole seconds from 60 to 86400, refusing to start with any other", async () => {
	const lasting = (written: string) =>
		booted({ runtime, config: { oidc: { "id-token-lifetime": written } } });
	for (const written of ["59s", "86401s", "300500ms"]) {
		await expect(lasting(written), written).rejects.toMatchObject({
			refusals: [{ where: "oidc.id-token-lifetime" }],
		});
	}
	await lasting("1m");
	await lasting("1d");
});

describe("the section", () => {
	it("reads the ID token's lifetime as an operator writes it, with a unit", async () => {
		expect(oidc.section?.parse({ "id-token-lifetime": "30m" })).toEqual({
			"id-token-lifetime": 1800,
		});
		const app = await booted({ runtime, config: { oidc: { "id-token-lifetime": "30m" } } });
		const { payload } = decoded(await makerOf(app).make(request()));
		expect(payload.exp - payload.iat).toBe(1800);
	});

	it("refuses to start with a lifetime that names no unit, a number or digits alone", async () => {
		const unitless = [
			[300, "written with its unit, such as 30s"],
			["300", "duration must name its unit"],
		] as const;
		for (const [written, reason] of unitless) {
			await expect(
				booted({ runtime, config: { oidc: { "id-token-lifetime": written } } }),
				String(written),
			).rejects.toMatchObject({ refusals: [{ where: "oidc.id-token-lifetime", reason }] });
		}
		const read = oidc.section?.safeParse({ "id-token-lifetime": "300" });
		expect(read?.error?.issues).toMatchObject([{ params: { problem: "missing-unit" } }]);
	});

	it("reads an empty section as an hour", () => {
		expect(oidc.section?.parse({})).toEqual({ "id-token-lifetime": 3600 });
	});
});

describe("the released claims an ID token carries", () => {
	const alice = { subject: "s-alice", clientId: "app", amr: ["pwd"], session: "h" };
	const sessionsAs = sessionsOf({ h: loginOf("s-alice", "users") });

	it("carries users' attributes through the table for the code's scope, beside the core claims [oidc-core-5.6-a]", async () => {
		const registered = testUser("alice", "pw", {
			subject: "s-alice",
			attributes: { [userAttribute.name]: "Alice", [userAttribute.email]: "alice@example.com" },
		});
		const maker = makerOf(await booted({ runtime, config: usersConfig([registered]), sessionsAs }));
		const { payload } = decoded(
			await maker.make(request({ ...alice, scope: ["openid", "profile"] })),
		);
		expect(payload).toMatchObject({ sub: "s-alice", name: "Alice", sid: "h" });
		expect(payload).not.toHaveProperty("email");
		expect(decoded(await maker.make(request(alice))).payload).not.toHaveProperty("name");
	});

	it("carries the session's login where users cannot look the subject up, and nothing beyond sub when neither can say", async () => {
		const maker = makerOf(
			await booted({ runtime, usersAs: [usersModule, unanswering], sessionsAs }),
		);
		const scope = ["openid", "profile", "email"];
		const { payload } = decoded(await maker.make(request({ ...alice, scope })));
		expect(payload).toMatchObject({
			name: "Al",
			email: "alice@login.example",
			email_verified: true,
		});
		const closed = decoded(await maker.make(request({ ...alice, scope, session: "x" })));
		expect(Object.keys(closed.payload).sort()).toEqual([
			"amr",
			"aud",
			"auth_time",
			"azp",
			"exp",
			"iat",
			"iss",
			"sid",
			"sub",
		]);
	});
});

describe("the claims a code's selection asks of the ID token", () => {
	const alice = { subject: "s-alice", clientId: "app", amr: ["pwd"], session: "h" };
	const registered = testUser("alice", "pw", {
		subject: "s-alice",
		attributes: { [userAttribute.name]: "Alice", [userAttribute.email]: "alice@example.com" },
	});
	const served = async () => {
		const app = await booted({
			runtime,
			config: { ...usersConfig([registered]), ...claimsSelectionConfig({ mode: "on" }) },
			sessionsAs: sessionsOf({ h: loginOf("s-alice", "users") }),
		});
		const [hook] = app.get(hooks);
		if (!hook) throw new Error("no hook");
		return { maker: makerOf(app), selections: app.get(claimsSelections), hook };
	};

	it("carries the names pinned for the ID token, held to their constraints, and never userinfo's", async () => {
		const { maker, selections, hook } = await served();
		await selections.keepForCode(
			"r-1",
			{
				idToken: {
					names: [{ name: "name", scope: "profile" }],
					constraints: [{ name: "email", value: "bob@example.com" }],
				},
				userinfo: { names: [{ name: "email", scope: "email" }], constraints: [] },
			},
			600_000,
		);
		await hook.pin("r-1");
		const { payload } = decoded(
			await maker.make(request({ ...alice, scope: ["openid", "email"], redemption: "r-1" })),
		);
		expect(payload).toMatchObject({ name: "Alice" });
		// email comes from the scope, but the ID token's constraint holds it back.
		expect(payload).not.toHaveProperty("email");
	});

	it("carries the scope's claims alone for a code pinned without a selection", async () => {
		const { maker, hook } = await served();
		await hook.pin("r-2");
		const { payload } = decoded(
			await maker.make(request({ ...alice, scope: ["openid", "email"], redemption: "r-2" })),
		);
		expect(payload).toMatchObject({ email: "alice@example.com" });
		expect(payload).not.toHaveProperty("name");
	});

	it("makes no ID token for a redemption whose pin is gone", async () => {
		const { maker } = await served();
		await expect(
			maker.make(request({ ...alice, scope: ["openid", "email"], redemption: "r-3" })),
		).rejects.toThrow();
	});
});

describe("issuer's metadata", () => {
	const items = async () => (await booted({ runtime })).get(published);

	it("names openid and the table's scopes as the scopes it supports, the ones OpenID Connect Core defines among them [oidc-discovery-3-s] [rfc8414-2-f] [oidc-discovery-3-u]", async () => {
		expect(await items()).toContainEqual({
			name: "scopes_supported",
			value: ["openid", "profile", "email", "groups"],
		});
	});

	it("names sub and the table's claims as the claims it supports [oidc-discovery-3-af]", async () => {
		expect(await items()).toContainEqual({
			name: "claims_supported",
			value: ["sub", "name", "picture", "email", "email_verified", "groups"],
		});
	});

	it("names that every client sees a user by the same subject [oidc-discovery-3-y] [oidc-core-8-a]", async () => {
		expect(await items()).toContainEqual({ name: "subject_types_supported", value: ["public"] });
	});

	it("names the algorithm ID tokens are signed with [oidc-discovery-3-z]", async () => {
		expect(await items()).toContainEqual({
			name: "id_token_signing_alg_values_supported",
			value: ["EdDSA"],
		});
	});
});

it("takes all it names, with users and with a ledger that cannot answer", async () => {
	const runtime = quietRuntime();
	for (const usersAs of [[usersModule], [usersModule, unanswering]]) {
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect((await takesUnused(composed({ runtime, usersAs })))["oidc"]).toBeUndefined();
	}
});
