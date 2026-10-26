import { generateKeyPairSync } from "node:crypto";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, takesUnused, unavailableSwitch } from "@mod/kernel/testing";
import { type AccessTokenSigning, accessTokenSigning } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import { senderBindings } from "@mod/sender-binding";
import senderBindingModule from "@mod/sender-binding/module";
import { beforeEach, describe, expect, it } from "vitest";
import {
	type AccessCondition,
	type AccessGrant,
	accessConditions,
	type IssueLimits,
	subjectChecks,
	type Tokens,
	tokens,
} from "../src/contract.ts";
import { defaultLifetimeSeconds } from "../src/limits.ts";
import tokensModule from "../src/module.ts";
import { section } from "../src/section.ts";
import { revokedInMemory } from "./revoked.ts";

const start = 1_800_000_000_000;
let now = start;
beforeEach(() => {
	now = start;
});
const runtime = quietRuntime({ clock: { now: () => now } });
const privateKey = generateKeyPairSync("ed25519")
	.privateKey.export({ format: "pem", type: "pkcs8" })
	.toString();

async function boot(...args: Parameters<typeof assembled>) {
	return (await assembled(...args)).get(tokens);
}

/** The grant most tests issue for; a test that is about the grant writes its own. */
const grant = { subject: "s", issuedTo: "c", audience: ["api"], scope: [] };

/** Issues through `issue`, which nothing here refuses, and answers what it issued. */
async function issueFor(t: Tokens, grant: AccessGrant, limits?: IssueLimits) {
	const issued = await t.issue({ grant, grantType: "test" }, limits);
	if (issued.kind !== "issued") throw new Error(`refused by ${issued.policy}`);
	return issued.access;
}
const claimsOf = (token: string) =>
	JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString());

/** The assembly the tests boot: keys, issuer, sender binding and tokens, with this tokens section. */
const assembly = (
	section: Record<string, unknown>,
	{
		extra = [],
		origin,
		issuerUrl = "https://issuer.example",
		keys = keysModule,
	}: {
		readonly extra?: Module[];
		readonly origin?: string;
		readonly issuerUrl?: string;
		readonly keys?: Module;
	} = {},
) => ({
	modules: [
		http,
		keys,
		issuerModule,
		senderBindingModule,
		tokensModule,
		revokedInMemory(() => runtime.clock.now()).module,
		...extra,
	],
	config: {
		...kernelConfig(),
		...httpConfig(origin ? { "public-origin": origin } : {}),
		// One key across boots, so a token from one boot can be read by another.
		...keysConfig({ signing: { kid: "k", alg: "EdDSA", "private-key": privateKey } }),
		...issuerConfig({ url: issuerUrl }),
		// Most tests compose no subject check, so the section states none unless a test says otherwise.
		tokens: { "subject-check": "none", ...section },
	},
	runtime,
});

async function assembled(...args: Parameters<typeof assembly>) {
	return assemble(assembly(...args));
}

describe("tokens", () => {
	it("issues access tokens that verify until they expire", async () => {
		const t = await boot({
			"access-token-lifetime": "1m",
			revocation: "unsupported",
		});
		const grant = { subject: "svc", issuedTo: "svc", audience: ["api"], scope: ["read", "write"] };
		const issued = await issueFor(t, grant);
		expect(issued.expiresIn).toBe(60);
		expect(await t.verifyAccess(issued.token)).toEqual({
			kind: "valid",
			id: issued.id,
			grant,
			expiresAt: now + 60_000,
			tokenType: "Bearer",
		});
		now = start + 60_000;
		expect(await t.verifyAccess(issued.token)).toEqual({ kind: "invalid", reason: "expired" });
	});

	it("caps the expiry at the limit it is given", async () => {
		const t = await boot({
			"access-token-lifetime": "1h",
			revocation: "unsupported",
		});
		expect((await issueFor(t, grant, { notAfter: now + 120_000 })).expiresIn).toBe(120);
		expect((await issueFor(t, grant, { notAfter: now + 7_200_000 })).expiresIn).toBe(3600);
	});

	it("stamps a binding into cnf, and takes the token type from the kind that writes the member", async () => {
		const kind = defineModule({ name: "binding-one", takes: [] }, (m) => [
			m.contribute(senderBindings).by(() => ({
				member: "one",
				tokenType: "ONE",
				read: async () => ({ kind: "absent" as const }),
			})),
		]);
		const t = await boot({ revocation: "unsupported" }, { extra: [kind] });
		const binding = { member: "one", confirmation: "thumb", tokenType: "ONE" };
		const issued = await issueFor(t, grant, { binding });
		expect(issued.tokenType).toBe("ONE");
		expect(await t.verifyAccess(issued.token)).toMatchObject({
			kind: "valid",
			tokenType: "ONE",
			binding,
		});
		expect((await issueFor(t, grant)).tokenType).toBe("Bearer");
		const unaware = await boot({ revocation: "unsupported" });
		expect(await unaware.verifyAccess(issued.token)).toEqual({ kind: "invalid", reason: "shape" });
	});

	it("refuses a revoked access token until it expires, and only that one", async () => {
		const t = await boot({ revocation: "denylist" });
		const first = await issueFor(t, grant);
		const second = await issueFor(t, grant);
		expect(await t.revokeAccess(first.token)).toEqual({ kind: "revoked" });
		expect(await t.verifyAccess(first.token)).toEqual({ kind: "invalid", reason: "revoked" });
		expect((await t.verifyAccess(second.token)).kind).toBe("valid");
		expect(await t.revokeAccess("garbage")).toEqual({ kind: "invalid" });
	});

	it("says revocation is unsupported where it was declared so", async () => {
		const t = await boot({ revocation: "unsupported" });
		const issued = await issueFor(t, grant);
		expect(await t.revokeAccess(issued.token)).toEqual({ kind: "unsupported" });
		expect(t.revocable()).toBe(false);
	});

	it("tells a grant the lifetime it applies, so the grant refuses boot above its ceiling", async () => {
		const ceilingSeconds = 900;
		const ceiling = contract<object>("ceiling-grant");
		const grantWithCeiling = defineModule({ name: "ceiling-grant", takes: [tokens] }, (m) => [
			m.provide(ceiling).by(async (c) => {
				const lifetime = (await c.get(tokens)).accessTokenLifetimeSeconds();
				if (lifetime > ceilingSeconds) {
					return c.refuse(
						"ceiling-grant",
						`lifetime ${lifetime} s is over the ceiling ${ceilingSeconds} s`,
					);
				}
				return {};
			}),
		]);
		const bootWith = (lifetime: string) =>
			assembled(
				{ "access-token-lifetime": lifetime, revocation: "unsupported" },
				{ extra: [grantWithCeiling] },
			);
		await expect(bootWith("15m")).resolves.toBeDefined();
		await expect(bootWith("14m")).resolves.toBeDefined();
		await expect(bootWith("901s")).rejects.toMatchObject({
			refusals: [{ where: "ceiling-grant", reason: "lifetime 901 s is over the ceiling 900 s" }],
		});
	});

	it("refuses to start until revocation is decided", async () => {
		await expect(boot({})).rejects.toBeInstanceOf(BootRefused);
	});
});

it("refuses a valid access token that a contributed condition no longer holds for, and lets unavailability through", async () => {
	const seen: { id: string; subject: string; issuedAt: number }[] = [];
	let answer: "holds" | "revoked" = "holds";
	const down = unavailableSwitch<AccessCondition>();
	const condition = defineModule({ name: "condition", takes: [] }, (m) => [
		m.contribute(accessConditions).by(() =>
			down.wrap({
				name: "test",
				holds: async (token) => {
					seen.push(token);
					return answer;
				},
			}),
		),
	]);
	const t = await boot({ revocation: "unsupported" }, { extra: [condition] });
	const issued = await issueFor(t, grant);
	expect((await t.verifyAccess(issued.token)).kind).toBe("valid");
	expect(seen).toEqual([{ id: issued.id, subject: "s", issuedAt: Math.floor(now / 1000) * 1000 }]);
	answer = "revoked";
	expect(await t.verifyAccess(issued.token)).toEqual({ kind: "invalid", reason: "revoked" });
	down.unavailable("holds");
	await expect(t.verifyAccess(issued.token)).rejects.toThrow(Unavailable);
});

it("asks the subject check whether a token's subject was revoked since it was issued", async () => {
	let answer: "holds" | "revoked" = "holds";
	const check = defineModule({ name: "check", takes: [] }, (m) => [
		m.contribute(subjectChecks).by(() => ({ holds: async () => answer })),
	]);
	const t = await boot(
		{ revocation: "unsupported", "subject-check": undefined },
		{ extra: [check] },
	);
	const issued = await issueFor(t, grant);
	expect((await t.verifyAccess(issued.token)).kind).toBe("valid");
	answer = "revoked";
	expect(await t.verifyAccess(issued.token)).toEqual({ kind: "invalid", reason: "revoked" });
});

it("refuses to start unless exactly one module checks subjects, or the section states that none does", async () => {
	const check = (name: string) =>
		defineModule({ name, takes: [] }, (m) => [
			m.contribute(subjectChecks).by(() => ({ holds: async () => "holds" as const })),
		]);
	const unchecked = {
		revocation: "unsupported",
		"subject-check": undefined,
	};
	const stated = { ...unchecked, "subject-check": "none" };
	const refused = { refusals: [{ where: "tokens.subject-check" }] };
	await expect(boot(unchecked)).rejects.toMatchObject(refused);
	await expect(boot(unchecked, { extra: [check("a"), check("b")] })).rejects.toMatchObject(refused);
	await expect(boot(stated, { extra: [check("a")] })).rejects.toMatchObject(refused);
	await boot(unchecked, { extra: [check("a")] });
	await boot(stated);
});

it("names and stamps the issuer that issuer owns", async () => {
	const t = await boot(
		{ revocation: "unsupported" },
		{ issuerUrl: "https://issuer.example/tenant" },
	);
	const issued = await issueFor(t, grant);
	expect(claimsOf(issued.token).iss).toBe("https://issuer.example/tenant");
	expect((await t.verifyAccess(issued.token)).kind).toBe("valid");
});

it("names among the issuer's metadata where the keys its tokens are signed with are published, on the public origin", async () => {
	let seen: readonly MetadataItem[] = [];
	const reader = defineModule({ name: "reader", takes: [metadata] }, (m) => [
		m.provide(contract<readonly MetadataItem[]>("seen")).by(async (c) => {
			seen = await c.collect(metadata);
			return seen;
		}),
	]);
	const jwks = (items: readonly MetadataItem[]) => items.find((i) => i.name === "jwks_uri")?.value;
	const section = { revocation: "unsupported" };
	await boot(section, {
		extra: [reader],
		origin: "https://as.example",
		issuerUrl: "https://as.example/tenant",
	});
	expect(jwks(seen)).toBe("https://as.example/.well-known/jwks.json");
	await boot(section, { extra: [reader] });
	expect(jwks(seen)).toBeUndefined();
});

it("writes the actor chain as act, and amr, auth_time and acr, only when the grant gives them", async () => {
	const t = await boot({ revocation: "unsupported" });
	const plain = claimsOf((await issueFor(t, { ...grant, amr: [] })).token);
	expect(["act", "amr", "auth_time", "acr"].filter((name) => name in plain)).toEqual([]);
	const issued = await issueFor(t, {
		...grant,
		actor: { subject: "a", actor: { subject: "b" } },
		amr: ["hwk", "pwd"],
		authenticatedAt: now - 1_500,
	});
	const claims = claimsOf(issued.token);
	expect(claims.act).toEqual({ sub: "a", act: { sub: "b" } });
	expect(claims.amr).toEqual(["hwk", "pwd"]);
	expect(claims.auth_time).toBe(Math.floor((now - 1_500) / 1000));
	const checked = await t.verifyAccess(issued.token);
	expect(checked.kind === "valid" && checked.grant).toEqual({
		...grant,
		actor: { subject: "a", actor: { subject: "b" } },
		amr: ["hwk", "pwd"],
		authenticatedAt: Math.floor((now - 1_500) / 1000) * 1000,
	});
});

it("writes no auth_time for a grant whose authentication time is not known, whatever time it holds", async () => {
	const t = await boot({ revocation: "unsupported" });
	const issued = await issueFor(t, {
		...grant,
		authenticatedAt: now - 1_500,
		authenticatedAtUnknown: true,
	});
	expect("auth_time" in claimsOf(issued.token)).toBe(false);
	const checked = await t.verifyAccess(issued.token);
	expect(checked.kind === "valid" && checked.grant.authenticatedAt).toBeUndefined();
});

it("refuses as shape a token whose act, amr or auth_time is malformed", async () => {
	const app = await assembled({ revocation: "unsupported" });
	const t = app.get(tokens);
	const issued = await issueFor(t, grant);
	const signer = app.get(accessTokenSigning);
	for (const malformed of [
		{ act: { sub: "a", act: { sub: 1 } } },
		{ act: "a" },
		{ amr: "hwk" },
		{ auth_time: "now" },
		{ acr: 7 },
		{ acr: "" },
	]) {
		const token = await signer.sign({ ...claimsOf(issued.token), ...malformed });
		expect(await t.verifyAccess(token), JSON.stringify(malformed)).toEqual({
			kind: "invalid",
			reason: "shape",
		});
	}
});

it("writes one audience as a string and more as a list, an empty scope not at all, and a 128-bit id", async () => {
	const t = await boot({ revocation: "unsupported" });
	const one = await issueFor(t, grant);
	expect(claimsOf(one.token)).toMatchObject({ aud: "api" });
	expect("scope" in claimsOf(one.token)).toBe(false);
	expect(one.id).toMatch(/^[A-Za-z0-9_-]{22}$/);
	const two = await issueFor(t, { ...grant, audience: ["a", "b"], scope: ["read"] });
	expect(claimsOf(two.token)).toMatchObject({ aud: ["a", "b"], scope: "read" });
});

it("refuses a token whose cap has passed, handing none out", async () => {
	const t = await boot({ revocation: "unsupported" });
	expect(await t.issue({ grant, grantType: "test" }, { notAfter: now - 10_000 })).toEqual({
		kind: "refused",
		policy: "tokens",
		reason: "no_lifetime_left",
		description: "expired",
	});
});

it("refuses a token another issuer stamped, and one bound by two members", async () => {
	const kinds = defineModule({ name: "two-kinds", takes: [] }, (m) =>
		["one", "two"].map((member) =>
			m.contribute(senderBindings).by(() => ({
				member,
				tokenType: member.toUpperCase(),
				read: async () => ({ kind: "absent" as const }),
			})),
		),
	);
	const app = await assembled({ revocation: "unsupported" }, { extra: [kinds] });
	const t = app.get(tokens);
	const signer = app.get(accessTokenSigning);
	const claims = claimsOf((await issueFor(t, grant)).token);
	const signed = (changed: Record<string, unknown>) => signer.sign({ ...claims, ...changed });
	expect(await t.verifyAccess(await signed({ iss: "https://other.example" }))).toEqual({
		kind: "invalid",
		reason: "issuer",
	});
	expect(await t.verifyAccess(await signed({ cnf: { one: "a", two: "b" } }))).toEqual({
		kind: "invalid",
		reason: "shape",
	});
	expect((await t.verifyAccess(await signed({ cnf: { two: "b" } }))).kind).toBe("valid");
});

it("answers unsupported to any revocation where revocation is not configured, a token or not", async () => {
	const t = await boot({ revocation: "unsupported" });
	expect(await t.revokeAccess("garbage")).toEqual({ kind: "unsupported" });
});

it("reads the access token's lifetime with its unit, in whole seconds, an hour unless set", () => {
	const lifetimeOf = (settings: object) =>
		section.safeParse({ revocation: "unsupported", ...settings }).data?.["access-token-lifetime"];
	expect([{}, { "access-token-lifetime": "2h" }].map(lifetimeOf)).toEqual([
		defaultLifetimeSeconds,
		7200,
	]);
	const refused = [
		{ "access-token-lifetime-seconds": 60 },
		{ "access-token-lifetime": 3600 },
		{ "access-token-lifetime": "1500ms" },
	];
	expect(refused.map(lifetimeOf)).toEqual([undefined, undefined, undefined]);
});

it("takes all it names under either revocation, the denylist only where it keeps one", async () => {
	for (const revocation of ["denylist", "unsupported"]) {
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect((await takesUnused(assembly({ revocation })))["tokens"], revocation).toBeUndefined();
	}
});

/** keys, its signing of an access token taking `signing.ms` on the kernel's clock: a remote signer, say. */
const signing = { ms: 0 };
const slowKeys: Module = {
	...keysModule,
	provides: (keysModule.provides ?? []).map((part) =>
		part.contract !== accessTokenSigning
			? part
			: {
					contract: part.contract,
					create: async (context: Parameters<typeof part.create>[0]) => {
						const real = (await part.create(context)) as AccessTokenSigning;
						return {
							...real,
							sign: async (claims: Readonly<Record<string, unknown>>) => {
								const token = await real.sign(claims);
								now += signing.ms;
								return token;
							},
						};
					},
				},
	),
};

describe("the lifetime answered, after the signing", () => {
	beforeEach(() => {
		signing.ms = 0;
	});
	const slow = () =>
		boot({ "access-token-lifetime": "1m", revocation: "unsupported" }, { keys: slowKeys });

	it("answers expiresIn from when the token is signed, its expiry as it was set", async () => {
		const t = await slow();
		expect(await issueFor(t, grant)).toMatchObject({ expiresIn: 60, expiresAt: start + 60_000 });
		now = start;
		signing.ms = 2500;
		// Rounded up to whole seconds: 57.5 left is 58.
		const late = await issueFor(t, grant);
		expect(late).toMatchObject({ expiresIn: 58, expiresAt: start + 60_000 });
		expect(claimsOf(late.token)).toMatchObject({ iat: start / 1000, exp: start / 1000 + 60 });
	});

	it("refuses a token its signing leaves less than a second, and answers what is left, rounded up, for one it does not", async () => {
		const t = await slow();
		const capped = { notAfter: start + 2000 };
		for (const ms of [3000, 2000, 1500]) {
			now = start;
			signing.ms = ms;
			expect(await t.issue({ grant, grantType: "test" }, capped), String(ms)).toMatchObject({
				kind: "refused",
				policy: "tokens",
				reason: "no_lifetime_left",
			});
		}
		for (const [ms, left] of [
			[1000, 1],
			[0, 2],
		] as const) {
			now = start;
			signing.ms = ms;
			const issued = await issueFor(t, grant, capped);
			expect([issued.expiresIn, issued.expiresAt], String(ms)).toEqual([left, start + 2000]);
		}
	});
});
