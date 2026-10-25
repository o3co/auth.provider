import type { HttpRequest } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig, type Module, Unavailable } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { testScryptHash } from "@mod/secret-hash/testing";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
	type Authentication,
	type AuthMethod,
	authMethods,
	type Client,
	type ClientRecord,
	type Clients,
	clientSources,
	clients,
	metadataSections,
	type Section,
} from "../src/contract.ts";
import clientsModule from "../src/module.ts";
import { clientRecord } from "../src/registry.ts";
import { basic, refusalsOf } from "./parts.ts";

const grants: Section<{ allowed: string[] }> = {
	name: "grants",
	schema: z.strictObject({ allowed: z.array(z.string()).default([]) }),
};
const grantsModule = defineModule({ name: "grants-owner", takes: [] }, (m) => [
	m.contribute(metadataSections).by(() => grants),
]);

const registered: unknown[] = [
	{
		id: "conf",
		kind: "confidential",
		method: "client_secret_basic",
		sections: { "client-secret": { hash: testScryptHash("s3cret") }, grants: { allowed: ["x"] } },
	},
	{
		id: "post",
		kind: "confidential",
		method: "client_secret_post",
		sections: { "client-secret": { hash: testScryptHash("p0st") } },
	},
	{ id: "pub", kind: "public", method: "none" },
];

async function boot(extra: readonly Module[] = [], list = registered): Promise<Clients> {
	const app = await assemble({
		modules: [clientsModule, secretHashModule, grantsModule, ...extra],
		config: { ...kernelConfig(), clients: { registered: list } },
	});
	return app.get(clients);
}

const method = (name: string, parts: Partial<AuthMethod> = {}) =>
	defineModule({ name, takes: [] }, (m) => [
		m.contribute(authMethods).by(() => ({
			name,
			claimed: () => undefined,
			verify: async () => true,
			...parts,
		})),
	]);
const source = (find: (id: string) => unknown) =>
	defineModule({ name: "source", takes: [] }, (m) => [
		m.contribute(clientSources).by(() => ({
			find: async (id: string) => find(id) as ClientRecord | undefined,
		})),
	]);

function request(headers: Record<string, string>, form: Record<string, string[]>): HttpRequest {
	return testRequest({
		method: "POST",
		headers: new Map(Object.entries(headers)),
		form: new Map(Object.entries(form)),
	});
}
const outcome = (c: Clients, h: Record<string, string>, f: Record<string, string[]>) =>
	c.authenticate(request(h, f));
const clientOf = (result: Authentication) => {
	if (result.kind !== "authenticated") throw new Error(`refused: ${result.reason}`);
	return result.client;
};
const bootRefusal = async (list: unknown[]) =>
	(await refusalsOf(boot([], list))).map((r) => r.where).sort();

describe("clients", () => {
	it("authenticates each built-in method and hands out the owner's section", async () => {
		const c = await boot();
		expect(clientOf(await outcome(c, basic("conf", "s3cret"), {})).section(grants)).toEqual({
			allowed: ["x"],
		});
		expect(
			clientOf(await outcome(c, {}, { client_id: ["post"], client_secret: ["p0st"] })).id,
		).toBe("post");
		expect(clientOf(await outcome(c, {}, { client_id: ["pub"] })).section(grants)).toEqual({
			allowed: [],
		});
	});

	it("lists the clients the operator registered, in the order the settings give them", async () => {
		const c = await boot();
		expect(c.registered().map((client) => [client.id, client.registered])).toEqual(
			(registered as readonly { readonly id: string }[]).map((r) => [r.id, true]),
		);
	});

	it("throws for a section no module contributed, never answering undefined", async () => {
		const c = await boot();
		const client = clientOf(await outcome(c, basic("conf", "s3cret"), {}));
		const stray: Section<{ on: boolean }> = {
			name: "stray",
			schema: z.strictObject({ on: z.boolean() }),
		};
		expect(() => client.section(stray)).toThrow(/stray/);
	});

	it("form-decodes the Basic id and secret", async () => {
		const id = "a+b %c";
		const c = await boot(
			[],
			[
				{
					id,
					kind: "confidential",
					method: "client_secret_basic",
					sections: { "client-secret": { hash: testScryptHash("s+e %t") } },
				},
			],
		);
		const raw = (decoded: string) => ({
			authorization: `Basic ${Buffer.from(decoded).toString("base64")}`,
		});
		expect(clientOf(await outcome(c, raw("a%2Bb+%25c:s%2Be%20%25t"), {})).id).toBe(id);
		expect(await outcome(c, raw("a%2Bb+%25c:s+e+%25t"), {})).toMatchObject({
			reason: "bad_credentials",
		});
	});

	it("refuses each way the credentials do not fit the client", async () => {
		const c = await boot();
		expect(await outcome(c, basic("conf", "nope"), {})).toMatchObject({
			reason: "bad_credentials",
		});
		expect(await outcome(c, basic("ghost", "x"), {})).toMatchObject({ reason: "unknown_client" });
		expect(await outcome(c, {}, { client_id: ["conf"], client_secret: ["s3cret"] })).toMatchObject({
			reason: "wrong_method",
		});
		expect(
			await outcome(c, basic("conf", "s3cret"), { client_id: ["post"], client_secret: ["p0st"] }),
		).toMatchObject({ reason: "multiple_methods" });
		expect(await outcome(c, {}, {})).toEqual({
			kind: "refused",
			reason: "no_credentials",
			challenges: ['Basic realm="client"'],
		});
		// A confidential client sending no secret is `none`, which is not its method.
		expect(await outcome(c, {}, { client_id: ["conf"] })).toMatchObject({ reason: "wrong_method" });
	});

	it("refuses a confidential client whose method is none", async () => {
		const c = await boot([], [{ id: "conf-none", kind: "confidential", method: "none" }]);
		expect(await outcome(c, {}, { client_id: ["conf-none"] })).toMatchObject({
			reason: "bad_credentials",
		});
	});

	it("refuses records whose sections do not fit, at each section's path", async () => {
		expect(
			await bootRefusal([
				{
					id: "a",
					kind: "public",
					method: "none",
					sections: { grants: { allowed: "x" }, ghost: {} },
				},
			]),
		).toEqual([
			"clients.registered.0.sections.ghost",
			"clients.registered.0.sections.grants.allowed",
		]);
	});

	describe("a section's boot check", () => {
		const checked = (seen: unknown[], holders: unknown[] = []) =>
			defineModule({ name: "checked-owner", takes: [] }, (m) => [
				m.contribute(metadataSections).by(() => ({
					name: "checked",
					schema: z.strictObject({ allowed: z.array(z.string()).default([]) }),
					checkAtBoot: (value: { allowed: string[] }, client: Client) => {
						seen.push(value);
						holders.push([client.id, client.section(grants)]);
						if (value.allowed.includes("blank")) return "";
						return value.allowed.includes("bad") ? "names a bad value" : undefined;
					},
				})),
			]);
		const pub = { kind: "public", method: "none" };

		it("refuses boot at the section's path, by the client's place and never its id", async () => {
			const list = [
				{ id: "ok", ...pub, sections: { checked: { allowed: ["fine"] } } },
				{ id: "no", ...pub, sections: { checked: { allowed: ["bad"] } } },
				// An empty reason is still a reason.
				{ id: "blank", ...pub, sections: { checked: { allowed: ["blank"] } } },
			];
			expect(await refusalsOf(boot([checked([])], list))).toEqual([
				{
					where: "clients.registered.1.sections.checked",
					reason: "names a bad value",
				},
				{
					where: "clients.registered.2.sections.checked",
					reason: "",
				},
			]);
		});

		it("boots when it gives no reason, passing only the clients that carry the section, after the schema", async () => {
			const seen: unknown[] = [];
			const holders: unknown[] = [];
			const list = [...registered, { id: "empty", ...pub, sections: { checked: {} } }];
			const c = await boot([checked(seen, holders)], list);
			expect(seen).toEqual([{ allowed: [] }]);
			// The client that holds the section comes with it, its other sections read as any reader does.
			expect(holders).toEqual([["empty", { allowed: [] }]]);
			expect(Object.isFrozen(seen[0])).toBe(true);
			// A section without a check is read as before.
			expect((await c.find("conf"))?.section(grants)).toEqual({ allowed: ["x"] });
		});

		it("is never given a client from a source", async () => {
			const seen: unknown[] = [];
			const remote = { id: "remote", ...pub, sections: { checked: { allowed: ["bad"] } } };
			const c = await boot([checked(seen), source((id) => (id === "remote" ? remote : undefined))]);
			expect((await c.find("remote"))?.id).toBe("remote");
			expect(seen).toEqual([]);
		});
	});

	// Each id no client can have: control and line-breaking characters, a BOM, a lone surrogate, too long.
	const unnameable = [
		"a\nb",
		"a\u0000",
		"\u007f",
		"a\u0085b",
		"a\u009fb",
		"a\u2028b",
		"a\u2029b",
	].concat(["\ufeffconf", "a\ud800b", "\udc00", "a".repeat(257)]);

	it("refuses a registered client id no client can have", async () => {
		const longest = "a".repeat(256);
		const c = await boot([], [{ id: longest, kind: "public", method: "none" }]);
		expect((await c.find(longest))?.registered).toBe(true);
		for (const id of unnameable) {
			expect(await bootRefusal([{ id, kind: "public", method: "none" }])).toEqual([
				"clients.registered.0.id",
			]);
		}
	});

	it("refuses a registered client of an empty id, an unknown method or a secret given as SHA-256, and an id registered twice", async () => {
		expect(await bootRefusal([{ id: "a", kind: "public", method: "ghost" }])).toEqual([
			"clients.registered.0.method",
		]);
		expect(await bootRefusal([{ id: "", kind: "public", method: "none" }])).toEqual([
			"clients.registered.0.id",
		]);
		const sha256 = "0".repeat(64);
		expect(
			await bootRefusal([
				{
					id: "a",
					kind: "confidential",
					method: "client_secret_post",
					sections: { "client-secret": { sha256 } },
				},
			]),
		).toEqual(["clients.registered.0.sections.client-secret"]);
		const pub = { kind: "public", method: "none" };
		expect(
			await bootRefusal([
				{ id: "a", ...pub },
				{ id: "a", ...pub },
			]),
		).toEqual(["clients.registered"]);
	});

	it("refuses credentials a method finds malformed, after two methods at once and before anything else", async () => {
		const half = method("half", {
			claimed: (r) => r.form.get("half_id")?.[0],
			malformed: (r) => r.form.has("half_id") !== r.form.has("half_proof"),
		});
		const c = await boot([half]);
		expect(await outcome(c, {}, { half_proof: ["p"] })).toMatchObject({
			reason: "malformed_credentials",
			challenges: [],
		});
		expect(await outcome(c, {}, { half_id: ["conf"] })).toMatchObject({
			reason: "malformed_credentials",
			challenges: [],
		});
		expect(await outcome(c, basic("conf", "s3cret"), { half_id: ["conf"] })).toMatchObject({
			reason: "multiple_methods",
			challenges: [],
		});
		expect(clientOf(await outcome(c, basic("conf", "s3cret"), {})).id).toBe("conf");
		expect(clientOf(await outcome(c, {}, { client_id: ["pub"] })).id).toBe("pub");
	});

	it("takes a client_id beside another method's credentials as that method's, never none as well", async () => {
		const half = method("half", { claimed: (r) => r.form.get("half_id")?.[0] });
		const c = await boot([half]);
		expect(
			await outcome(c, {}, { client_id: ["conf"], half_id: ["conf"], half_proof: ["p"] }),
		).toMatchObject({ reason: "wrong_method", challenges: [] });
		// Not even a client_id that would be malformed for none.
		expect(await outcome(c, {}, { client_id: ["a", "b"], half_id: ["conf"] })).toMatchObject({
			reason: "wrong_method",
		});
	});

	it("refuses a Basic header or a client_secret that does not name one client as malformed, asking no source", async () => {
		const asked: string[] = [];
		const c = await boot([source((id) => void asked.push(id))]);
		const raw = (decoded: string) => ({
			authorization: `Basic ${Buffer.from(decoded).toString("base64")}`,
		});
		for (const headers of [
			raw("%"),
			raw("conf"),
			raw("%zz:s3cret"),
			raw("conf:%"),
			raw(":s3cret"),
			raw("conf:"),
			{ authorization: "Basic" },
			{ authorization: "Basic !!!!" },
		]) {
			expect(await outcome(c, headers, {})).toEqual({
				kind: "refused",
				reason: "malformed_credentials",
				challenges: [],
			});
		}
		for (const form of [
			{ client_secret: ["p0st"] },
			{ client_id: [""], client_secret: ["p0st"] },
			{ client_id: ["post", "post"], client_secret: ["p0st"] },
			{ client_id: ["post"], client_secret: ["p0st", "p0st"] },
			{ client_id: ["pub", "pub"] },
			{ client_id: ["", ""] },
		]) {
			expect(await outcome(c, {}, form)).toMatchObject({ reason: "malformed_credentials" });
		}
		const bearer = { authorization: "Bearer abc" };
		expect(await outcome(c, bearer, { client_id: ["pub", "pub"] })).toMatchObject({
			reason: "malformed_credentials",
		});
		expect(asked).toEqual([]);
	});

	it("takes an empty client_id alone as no credentials", async () => {
		const c = await boot();
		expect(await outcome(c, {}, { client_id: [""] })).toMatchObject({ reason: "no_credentials" });
	});

	it("refuses two methods' credentials as two methods, even when malformed", async () => {
		const c = await boot();
		const undecodable = { authorization: `Basic ${Buffer.from("conf").toString("base64")}` };
		expect(
			await outcome(c, undecodable, { client_id: ["post"], client_secret: ["p0st"] }),
		).toMatchObject({ reason: "multiple_methods" });
		expect(await outcome(c, basic("conf", "s3cret"), { client_secret: ["p0st"] })).toMatchObject({
			reason: "multiple_methods",
		});
	});

	it("reads a Basic header only in canonical base64 of UTF-8", async () => {
		const c = await boot();
		const header = (value: string) => ({ authorization: `Basic ${value}` });
		expect(Buffer.from("conf:s3cret").toString("base64")).toBe("Y29uZjpzM2NyZXQ=");
		expect(clientOf(await outcome(c, header("Y29uZjpzM2NyZXQ="), {})).id).toBe("conf");
		const invalidUtf8 = Buffer.concat([Buffer.from("conf:s3cret"), Buffer.from([0xff])]);
		for (const value of [
			"Y29uZjpzM2NyZXQ",
			"Y29uZjpzM2NyZXR=",
			"Y29u=ZjpzM2NyZXQ=",
			"Y29uZjpzM2NyZXQ==",
			"Y29uZjpzM2NyZXQ= x",
			"Y29uZjpzM2NyZXQ=!",
			invalidUtf8.toString("base64"),
		]) {
			expect(await outcome(c, header(value), {})).toMatchObject({
				reason: "malformed_credentials",
			});
		}
		for (const scheme of ["basic ", "BASIC ", "Basic  "]) {
			const authorization = `${scheme}Y29uZjpzM2NyZXQ=`;
			expect(clientOf(await outcome(c, { authorization }, {})).id).toBe("conf");
		}
		const bom = Buffer.from("\ufeffconf:s3cret").toString("base64");
		expect(await outcome(c, header(bom), {})).toMatchObject({ reason: "unknown_client" });
	});

	it("takes a client_id beside an Authorization header no method reads as none", async () => {
		const c = await boot();
		const bearer = { authorization: "Bearer abc" };
		expect(clientOf(await outcome(c, bearer, { client_id: ["pub"] })).id).toBe("pub");
		expect(await outcome(c, bearer, { client_id: ["conf"] })).toMatchObject({
			reason: "wrong_method",
		});
		expect(await outcome(c, bearer, {})).toMatchObject({ reason: "no_credentials" });
		// A scheme that only starts with "Basic" is not Basic.
		const joined = { authorization: "BasicY29uZjpzM2NyZXQ=" };
		expect(clientOf(await outcome(c, joined, { client_id: ["pub"] })).id).toBe("pub");
	});

	it("answers an id no client can have as unknown, asking no source", async () => {
		const asked: string[] = [];
		const c = await boot([
			source((id) => {
				asked.push(id);
				return { id, kind: "public", method: "none", sections: {} };
			}),
		]);
		for (const id of unnameable) {
			expect(await c.find(id)).toBeUndefined();
			expect(await outcome(c, {}, { client_id: [id] })).toEqual({
				kind: "refused",
				reason: "unknown_client",
				challenges: [],
			});
			// A lone surrogate has no UTF-8 form, so no Basic header carries it.
			if (!id.isWellFormed()) continue;
			expect(await outcome(c, basic(id, "x"), {})).toEqual({
				kind: "refused",
				reason: "unknown_client",
				challenges: ['Basic realm="client"'],
			});
		}
		expect(await c.find("")).toBeUndefined();
		expect(asked).toEqual([]);
		expect((await c.find("a b"))?.id).toBe("a b");
		expect((await c.find("a".repeat(256)))?.id).toBe("a".repeat(256));
		expect(asked).toEqual(["a b", "a".repeat(256)]);
	});

	it("checks a source's record by the rule for a registered one, and against the id asked", async () => {
		const good = { kind: "public", method: "none", sections: {} };
		const answers: Record<string, unknown> = {
			good: { id: "good", ...good },
			bare: { id: "bare", kind: "public", method: "none" },
			kind: { ...good, id: "kind", kind: "secret" },
			method: { ...good, id: "method", method: "ghost" },
			extra: { ...good, id: "extra", note: "x" },
			other: { ...good, id: "good" },
			section: { ...good, id: "section", sections: { grants: { allowed: 1 } } },
			throws: {
				...good,
				get id(): string {
					throw new Error("unreadable");
				},
			},
			getter: {
				...good,
				id: "getter",
				sections: {
					grants: {
						get allowed(): string[] {
							throw new Error("unreadable");
						},
					},
				},
			},
			proxy: {
				...good,
				id: "proxy",
				sections: {
					grants: new Proxy(
						{},
						{
							get: () => {
								throw new Error("unreadable");
							},
						},
					),
				},
			},
		};
		const c = await boot([source((id) => answers[id])]);
		expect((await c.find("good"))?.id).toBe("good");
		expect((await c.find("bare"))?.id).toBe("bare");
		for (const id of ["kind", "method", "extra", "other", "section", "throws", "getter", "proxy"]) {
			expect(await c.find(id)).toBeUndefined();
			expect(await outcome(c, {}, { client_id: [id] })).toMatchObject({
				reason: "invalid_record",
			});
		}
	});

	it("checks a record as find holds a source's, answering where each part fails and never a value", async () => {
		const c = await boot();
		const good = { id: "doc", kind: "public", method: "none", sections: {} };
		const pathsOf = async (record: unknown) =>
			(await c.checkRecord(record as ClientRecord))?.map((refusal) => refusal.path);
		expect(await c.checkRecord(good as ClientRecord)).toBeUndefined();
		expect(await pathsOf({ ...good, sections: { grants: { allowed: ["a"] } } })).toBeUndefined();
		expect(await pathsOf({ ...good, kind: "secret" })).toEqual(["kind"]);
		expect(await pathsOf({ ...good, id: "" })).toEqual(["id"]);
		expect(await pathsOf({ ...good, note: "x" })).toEqual(["note"]);
		expect(await pathsOf({ ...good, method: "ghost" })).toEqual(["method"]);
		expect(await pathsOf({ ...good, sections: { ghost: {} } })).toEqual(["sections.ghost"]);
		expect(await pathsOf({ ...good, sections: { grants: { allowed: ["a", 2] } } })).toEqual([
			"sections.grants.allowed.1",
		]);
		const refused = await c.checkRecord({
			...good,
			kind: "s3cret-kind",
			sections: { grants: { allowed: "s3cret-allowed" } },
		} as never);
		expect(JSON.stringify(refused)).not.toContain("s3cret");
		expect(refused?.map((refusal) => Object.keys(refusal))).toEqual([["path"]]);
		const unreadable = new Proxy(
			{},
			{
				get: () => {
					throw new Error("unreadable");
				},
			},
		);
		await expect(
			c.checkRecord({ ...good, sections: { grants: unreadable } } as ClientRecord),
		).rejects.toThrow("unreadable");
	});

	it("answers an authenticated client with its method's challenge, or every method's when it has none", async () => {
		const challenged = method("challenged", {
			challenge: 'Challenged realm="x"',
			claimed: (r) => r.form.single("challenged_id"),
		});
		const own = { id: "own", kind: "confidential", method: "challenged" };
		const c = await boot([challenged], [...registered, own]);
		const authenticated = (challenges: string[]) => ({ kind: "authenticated", challenges });
		const every = authenticated(['Basic realm="client"', 'Challenged realm="x"']);
		expect(await outcome(c, basic("conf", "s3cret"), {})).toMatchObject(
			authenticated(['Basic realm="client"']),
		);
		expect(await outcome(c, {}, { challenged_id: ["own"] })).toMatchObject(
			authenticated(['Challenged realm="x"']),
		);
		expect(await outcome(c, {}, { client_id: ["post"], client_secret: ["p0st"] })).toMatchObject(
			every,
		);
		expect(await outcome(c, {}, { client_id: ["pub"] })).toMatchObject(every);
		expect(await outcome(await boot(), {}, { client_id: ["pub"] })).toMatchObject({
			challenges: ['Basic realm="client"'],
		});
	});

	it("reads client_id and client_secret from a JSON body as from a form", async () => {
		const c = await boot();
		const json = (body: Record<string, unknown>) =>
			c.authenticate(testRequest({ method: "POST", json: body }));
		expect(clientOf(await json({ client_id: "pub" })).id).toBe("pub");
		expect(clientOf(await json({ client_id: "post", client_secret: "p0st" })).id).toBe("post");
		expect(await json({ client_id: "post", client_secret: "nope" })).toMatchObject({
			reason: "bad_credentials",
		});
		for (const other of [1, null, ["pub"], { id: "pub" }]) {
			for (const body of [
				{ client_id: "post", client_secret: other },
				{ client_id: other, client_secret: "p0st" },
				{ client_id: other },
			]) {
				expect(await json(body)).toMatchObject({ reason: "malformed_credentials" });
			}
		}
	});

	it("refuses a Basic header beside a client_id that names another client", async () => {
		const c = await boot();
		const beside = (client_id: string[]) => outcome(c, basic("conf", "s3cret"), { client_id });
		expect(clientOf(await beside(["conf"])).id).toBe("conf");
		for (const ids of [["pub"], ["conf", "conf"], [""]]) {
			expect(await beside(ids)).toEqual({
				kind: "refused",
				reason: "bad_credentials",
				challenges: ['Basic realm="client"'],
			});
		}
		const json = testRequest({
			method: "POST",
			headers: new Map(Object.entries(basic("conf", "s3cret"))),
			json: { client_id: 1 },
		});
		expect(await c.authenticate(json)).toMatchObject({ reason: "bad_credentials" });
	});

	it("names the ways a client can authenticate", async () => {
		expect([...(await boot()).methods()].sort()).toEqual([
			"client_secret_basic",
			"client_secret_post",
			"none",
		]);
	});

	it("names the algorithms methods sign credentials with, once each, and none when no method signs", async () => {
		expect((await boot()).signingAlgorithms()).toEqual([]);
		const c = await boot([
			method("a", { signingAlgorithms: ["ES256", "RS256"] }),
			method("b", { signingAlgorithms: ["RS256", "EdDSA"] }),
		]);
		expect(c.signingAlgorithms()).toEqual(["ES256", "RS256", "EdDSA"]);
	});

	it("says whether the operator registered a client, or a source named it", async () => {
		const remote = { kind: "public", method: "none", sections: {} };
		const c = await boot([source((id) => (id === "remote" ? { id, ...remote } : undefined))]);
		expect((await c.find("conf"))?.registered).toBe(true);
		expect((await c.find("remote"))?.registered).toBe(false);
	});

	it("throws unavailable when a source is unavailable, from find and authenticate", async () => {
		const c = await boot([
			source(() => {
				throw new Unavailable("test source");
			}),
		]);
		await expect(c.find("remote")).rejects.toBeInstanceOf(Unavailable);
		await expect(outcome(c, {}, { client_id: ["remote"] })).rejects.toBeInstanceOf(Unavailable);
		// A registered client never asks a source.
		expect((await c.find("conf"))?.id).toBe("conf");
	});

	it("asks the sources in turn until one names the client", async () => {
		const remote = { kind: "public" as const, method: "none", sections: {} };
		const later = defineModule({ name: "later", takes: [] }, (m) => [
			m.contribute(clientSources).by(() => ({
				find: async (id: string) => (id === "later" ? { id, ...remote } : undefined),
			})),
		]);
		const c = await boot([source((id) => (id === "first" ? { id, ...remote } : undefined)), later]);
		expect((await c.find("first"))?.id).toBe("first");
		expect((await c.find("later"))?.id).toBe("later");
	});

	it("hands out frozen clients and sections, registered or from a source", async () => {
		const remote = { kind: "public", method: "none", sections: { grants: { allowed: ["y"] } } };
		const c = await boot([source((id) => (id === "remote" ? { id, ...remote } : undefined))]);
		for (const id of ["conf", "remote"]) {
			const client = await c.find(id);
			expect(Object.isFrozen(client)).toBe(true);
			expect(Object.isFrozen(client?.section(grants).allowed)).toBe(true);
		}
	});
});

it("registers no clients, and a client no sections, that the operator leaves out", () => {
	expect(clientsModule.section?.parse({})).toEqual({ registered: [] });
	const written = { id: "c", kind: "public", method: "none" };
	expect(clientRecord.parse(written)).toEqual({ ...written, sections: {} });
});

it("takes every handle its takes name", async () => {
	const modules = [clientsModule, secretHashModule, grantsModule];
	const config = { ...kernelConfig(), clients: { registered } };
	expect((await takesUnused({ modules, config })).clients).toBeUndefined();
});
