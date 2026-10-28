import { clientAllowance } from "@mod/client-allowance";
import { type DocumentCopy, documentCopies } from "@mod/client-documents";
import { type Client, clients, metadataSections, type Section } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { publicClient } from "@mod/clients/testing";
import { clientCopy, clientSection } from "@mod/consent";
import { composedGrants } from "@mod/grants";
import { metadata } from "@mod/issuer";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import {
	DestinationRefused,
	type Narrower,
	type OutboundRequest,
	type OutboundResponse,
	OutboundUnavailable,
	outbound,
} from "@mod/outbound";
import { type Limits, outboundLimits } from "@mod/outbound-policy";
import { redirects, redirectsCopy } from "@mod/redirect-uris";
import secretHashModule from "@mod/secret-hash/module";
import { beforeEach, describe, expect, it } from "vitest";
import { z } from "zod";
import clientsCimd from "../src/module.ts";
import { section } from "../src/section.ts";

const id = "https://app.example/client.json";
const document = {
	client_id: id,
	client_name: "  App  ",
	client_uri: "https://app.example/",
	redirect_uris: ["https://app.example/cb"],
	scope: "read admin",
};

interface Sent {
	readonly url: string;
	readonly request: OutboundRequest | undefined;
	readonly narrower: Narrower | undefined;
}
const sent: Sent[] = [];
let answer: (url: string) => OutboundResponse | Promise<OutboundResponse> = () => json(document);
let now = 1_000_000;

function json(body: unknown, headers: Record<string, string> = {}, status = 200): OutboundResponse {
	return {
		status,
		headers: new Map(Object.entries({ "content-type": "application/json", ...headers })),
		body: new TextEncoder().encode(JSON.stringify(body)),
	};
}

/** The operator's caps outbound answers: wide enough for the defaults, unless a test narrows them. */
const wideCaps: Limits = { maxBytes: 65_536, timeoutMs: 5_000 };

/** Outbound as a test stand-in: it records each request and answers from the script, under the caps given. */
const outboundStandIn = (caps: Limits = wideCaps, lookups?: number) =>
	defineModule({ name: "outbound", replicaSafe: false, takes: [] }, (m) => [
		m.provide(outbound).by(() => ({
			fetch: async (url, request, narrower) => {
				sent.push({ url, request, narrower });
				return answer(url);
			},
		})),
		m.provide(outboundLimits).by(() => ({
			of: () => caps,
			...(lookups === undefined ? {} : { lookupsOf: () => lookups }),
		})),
	]);

/** client-allowance's section, taken as written. */
const allowanceSection: Section<unknown> = {
	name: "client-allowance",
	schema: z.record(z.string(), z.unknown()),
};

/** The owners' sections, and their copies from a document, as client-documents collects them. */
const ownersOf = (sections: readonly Section<unknown>[], copies: readonly DocumentCopy[]) =>
	defineModule({ name: "owners", replicaSafe: false, takes: [] }, (m) => [
		...sections.map((one) => m.contribute(metadataSections).by(() => one)),
		...copies.map((one) => m.contribute(documentCopies).by(() => one)),
	]);

/** The sections a document record carries, as their owners contribute them, with their copies. */
const owners = ownersOf([redirects, clientSection, allowanceSection], [redirectsCopy, clientCopy]);

/** Token-endpoint as a test stand-in: only the grant types it says are composed. */
const tokenEndpointStandIn = (composed: readonly string[]) =>
	defineModule({ name: "token-endpoint", replicaSafe: false, takes: [] }, (m) => [
		m.provide(composedGrants).by(() => new Set(composed)),
	]);

const items = contract<readonly { name: string; value: unknown }[]>("test.metadata");
const collector = defineModule(
	{ name: "test-collector", replicaSafe: true, takes: [metadata] },
	(m) => [m.provide(items).by((c) => c.collect(metadata))],
);

async function boot(
	settings: Record<string, unknown> = {},
	options: {
		code?: boolean;
		registered?: unknown[];
		caps?: Limits;
		/** How many names outbound lets the document's requests resolve at once; unanswered unless set. */
		lookups?: number;
		extra?: Module[];
		owners?: Module;
	} = {},
) {
	const recording = recordingLog();
	const input = {
		modules: [
			outboundStandIn(options.caps, options.lookups),
			clientsModule,
			secretHashModule,
			options.owners ?? owners,
			tokenEndpointStandIn(options.code === false ? [] : ["authorization_code"]),
			clientsCimd,
			collector,
			...(options.extra ?? []),
		],
		config: {
			...kernelConfig(),
			clients: { registered: options.registered ?? [] },
			// Any host, unless the test names the hosts.
			"clients-cimd": {
				scopes: ["openid", "read"],
				...(settings.allow === undefined ? { "allow-any-host": true } : {}),
				...settings,
			},
		},
		runtime: quietRuntime({ clock: { now: () => now }, log: recording.log }),
	};
	const app = await assemble(input);
	return {
		input,
		find: (given = id) => app.get(clients).find(given),
		supported: () =>
			app.get(items).find((item) => item.name === "client_id_metadata_document_supported")?.value,
		/** What was logged past the start's warning of any host taken. */
		lines: () => recording.lines().filter((line) => line.event !== "clients-cimd.any_host_allowed"),
		/** What the start warned of the hosts. */
		warned: () =>
			recording.lines().filter((line) => line.event === "clients-cimd.any_host_allowed"),
	};
}

/** The client the default boot finds for the default id, under the answer the test set. */
const documentClient = async () => (await (await boot()).find()) as Client;

beforeEach(() => {
	sent.length = 0;
	answer = () => json(document);
	now = 1_000_000;
});

describe("clients-cimd: a document client", () => {
	it("is a public client by none, never registered, from one GET asking for JSON within the caps", async () => {
		const client = await documentClient();
		expect(client).toMatchObject({ id, kind: "public", method: "none", registered: false });
		expect(sent).toEqual([
			{
				url: id,
				request: { headers: { accept: "application/json" } },
				narrower: { maxBytes: 5120, timeoutMs: 5000, outsideChosen: true },
			},
		]);
	});

	it("keeps the scopes the document asks within the operator's, and refresh only when named", async () => {
		const client = await documentClient();
		expect(clientAllowance.allowsGrant(client, "authorization_code")).toBe(true);
		expect(clientAllowance.allowsGrant(client, "refresh_token")).toBe(false);
		expect(clientAllowance.covers(client, { scope: ["read"], audience: ["i"] }, "i")).toBe(true);
		expect(clientAllowance.covers(client, { scope: ["admin"], audience: ["i"] }, "i")).toBe(false);
		answer = () => json({ ...document, grant_types: ["authorization_code", "refresh_token"] });
		const refreshing = await documentClient();
		expect(clientAllowance.allowsGrant(refreshing, "refresh_token")).toBe(true);
	});

	it("shows the trimmed name cut to 200 characters, the page and the verified host", async () => {
		answer = () => json({ ...document, client_name: ` ${"n".repeat(250)} ` });
		const client = await documentClient();
		expect(client.section(clientSection)).toEqual({
			"first-party": false,
			name: "n".repeat(200),
			uri: "https://app.example/",
			host: "app.example",
		});
	});

	it("is said in the metadata, only with the code grant composed", async () => {
		expect((await boot()).supported()).toBe(true);
		expect((await boot({}, { code: false })).supported()).toBeUndefined();
	});
});

describe("clients-cimd: none, without fetching", () => {
	it("when the code grant is not composed", async () => {
		expect(await (await boot({}, { code: false })).find()).toBeUndefined();
		expect(sent).toEqual([]);
	});

	it("for an id that is not a document URL", async () => {
		const app = await boot();
		for (const given of [
			"app",
			"https://app.example./c",
			"https://APP.example/c",
			"https://localhost/c",
		]) {
			expect(await app.find(given)).toBeUndefined();
		}
		expect(sent).toEqual([]);
	});

	it("for a denied host, the names under a dotted entry included, deny before allow", async () => {
		const app = await boot({ deny: [".example"], allow: ["app.example"] });
		expect(await app.find()).toBeUndefined();
		expect(await app.find("https://example/c")).toBeUndefined();
		expect(sent).toEqual([]);
	});

	it("for a host outside a non-empty allow list, which also narrows outbound's hosts", async () => {
		const app = await boot({ allow: [".corp.example"] });
		expect(await app.find()).toBeUndefined();
		expect(sent).toEqual([]);
		await app.find("https://a.corp.example/c");
		await app.find("https://corp.example/c");
		expect(sent.map((one) => one.narrower?.hosts)).toEqual([[".corp.example"], [".corp.example"]]);
	});

	it("for a refused host, logging only the refusal and the id's host", async () => {
		const app = await boot({ deny: ["app.example"], allow: [".corp.example"] });
		await app.find(`${id}?`);
		await app.find();
		await app.find("https://other.example/c");
		expect(app.lines()).toEqual([
			{
				level: "warn",
				event: "clients-cimd.host_refused",
				fields: { host: "app.example", reason: "denied" },
			},
			{
				level: "warn",
				event: "clients-cimd.host_refused",
				fields: { host: "other.example", reason: "not allowed" },
			},
		]);
	});

	it("for the id of a registered client, which wins as registered", async () => {
		const app = await boot({}, { registered: [publicClient({ id })] });
		expect(await app.find()).toMatchObject({ id, registered: true });
		expect(sent).toEqual([]);
	});
});

describe("clients-cimd: a refused document", () => {
	it.each([
		["another status", () => json(document, {}, 404)],
		["a content type not JSON", () => json(document, { "content-type": "text/plain" })],
		["not one object", () => json([document])],
		["a refused field", () => json({ ...document, client_secret: "s" })],
		["a refused destination", () => Promise.reject(new DestinationRefused("special-address"))],
		[
			"a refused destination, from a second bundled copy of outbound-policy",
			() =>
				Promise.reject(
					Object.assign(new Error("outbound destination refused: special-address"), {
						[Symbol.for("@mod/outbound-policy.destination-refused")]: true,
						reason: "special-address",
					}),
				),
		],
		["an answer past the size", () => Promise.reject(new OutboundUnavailable("too-large"))],
		["a host not reached", () => Promise.reject(new OutboundUnavailable("unreachable"))],
		[
			"an answer outbound does not take",
			() => Promise.reject(new OutboundUnavailable("unsupported-answer")),
		],
		[
			"an answer past the size, from a second bundled copy of outbound",
			() =>
				Promise.reject(
					Object.assign(new Error("outbound unavailable"), {
						[Symbol.for("@mod/outbound.unavailable")]: true,
						failure: "too-large",
					}),
				),
		],
	])("is none for %s, remembered for the refusal time", async (_, given) => {
		answer = given;
		const app = await boot();
		expect(await app.find()).toBeUndefined();
		now += 59_999;
		expect(await app.find()).toBeUndefined();
		expect(sent).toHaveLength(1);
		now += 1;
		await app.find();
		expect(sent).toHaveLength(2);
	});

	it.each([
		["plain http", "http://app.example/cb"],
		["a fragment", "https://app.example/cb#f"],
		["a response parameter in the query", "https://app.example/cb?code=1"],
	])("is none as a whole for a redirect URI with %s", async (_, uri) => {
		answer = () => json({ ...document, redirect_uris: ["https://app.example/ok", uri] });
		expect(await (await boot()).find()).toBeUndefined();
	});

	it("is none when an owner's schema refuses its record, logged with where and remembered for the refusal time", async () => {
		answer = () => json({ ...document, redirect_uris: ["http://app.example/cb"] });
		const app = await boot();
		expect(await app.find()).toBeUndefined();
		now += 59_999;
		expect(await app.find()).toBeUndefined();
		expect(sent).toHaveLength(1);
		now += 1;
		await app.find();
		expect(sent).toHaveLength(2);
		expect(app.lines()[0]).toEqual({
			level: "warn",
			event: "clients-cimd.document_refused",
			fields: { client: id, reason: "record at sections.authorize.redirect-uris.0" },
		});
	});

	it("is none and forgotten, as a failed fetch, when checking its record throws", async () => {
		const throwing = defineModule(
			{ name: "throwing-owner", replicaSafe: false, takes: [] },
			(m) => [
				m.contribute(metadataSections).by(() => ({
					name: "throwing",
					schema: z.unknown().transform(() => {
						throw new Error("unreadable");
					}),
				})),
			],
		);
		const app = await boot({}, { extra: [throwing] });
		expect(await app.find()).toBeUndefined();
		expect(await app.find()).toBeUndefined();
		expect(sent).toHaveLength(2);
	});

	it("takes a JSON media type with parameters or a +json suffix", async () => {
		answer = () => json(document, { "content-type": "application/json; charset=utf-8" });
		expect(await (await boot()).find()).toBeDefined();
		answer = () => json(document, { "content-type": "application/client+json" });
		expect(await (await boot()).find()).toBeDefined();
		answer = () => json(document, { "content-type": "Application/JSON" });
		expect(await (await boot()).find()).toBeDefined();
	});

	it("is logged with the status for any status but 200", async () => {
		answer = () => json(document, {}, 201);
		const app = await boot();
		expect(await app.find()).toBeUndefined();
		expect(app.lines()[0]?.fields).toEqual({ client: id, reason: "status 201" });
	});

	it("is logged with the id cut and the reason", async () => {
		// Long enough to be cut in the log, short enough that clients still asks the source (ids end at 256).
		const long = `https://app.example/${"a".repeat(220)}`;
		answer = () => json({ ...document, client_id: "other" });
		const app = await boot();
		await app.find(long);
		await app.find(id);
		const [line] = app.lines();
		expect(line).toMatchObject({ level: "warn", event: "clients-cimd.document_refused" });
		expect(line?.fields).toEqual({ client: long.slice(0, 200), reason: "client_id" });
		expect(app.lines()[1]?.fields).toEqual({ client: id, reason: "client_id" });
	});
});

describe("clients-cimd: the sections a document's record is built from", () => {
	const allowanceCopy: DocumentCopy = {
		section: allowanceSection,
		reads: [],
		copy: () => ({ value: { grants: ["password"] } }),
	};
	const sections = [redirects, clientSection, allowanceSection];
	const refusedBoot = (owners: Module) =>
		boot({}, { owners }).then(
			() => [],
			(error: BootRefused) => error.refusals.map((r) => r.reason),
		);

	it("refuses boot where no composed copy reads a field a document client needs", async () => {
		expect(await refusedBoot(ownersOf(sections, [redirectsCopy]))).toEqual([
			"no composed section reads a document's client_name",
		]);
		expect(await refusedBoot(ownersOf(sections, [clientCopy]))).toEqual([
			"no composed section reads a document's redirect_uris",
		]);
	});

	it("takes the copies client-documents collects, never a section's own fromDocument", async () => {
		expect(await refusedBoot(ownersOf(sections, []))).toEqual([
			"no composed section reads a document's redirect_uris",
			"no composed section reads a document's client_name",
		]);
	});

	it("refuses boot where a copy's section is not composed", async () => {
		expect(
			await refusedBoot(ownersOf([redirects, allowanceSection], [redirectsCopy, clientCopy])),
		).toEqual(["consent is copied from a document, and its section is not composed"]);
	});

	it("refuses boot where a section it computes is copied from a document by its owner", async () => {
		expect(
			await refusedBoot(ownersOf(sections, [redirectsCopy, clientCopy, allowanceCopy])),
		).toEqual(["client-allowance is computed here, and copied from a document by its owner too"]);
	});

	it("is none, logged with where, for a page the consent section refuses", async () => {
		answer = () => json({ ...document, client_uri: "http://app.example/" });
		const app = await boot();
		expect(await app.find()).toBeUndefined();
		expect(app.lines()[0]?.fields).toEqual({
			client: id,
			reason: "record at sections.consent.uri",
		});
	});
});

describe("clients-cimd: a failed fetch", () => {
	it.each([
		["running out of time", new OutboundUnavailable("timeout")],
		["outbound being busy", new OutboundUnavailable("busy")],
		["an unavailable of no kind", new Unavailable("outbound")],
	])("is none and not remembered for %s", async (_, error) => {
		answer = () => Promise.reject(error);
		const app = await boot();
		expect(await app.find()).toBeUndefined();
		await app.find();
		expect(sent).toHaveLength(2);
	});

	it("is logged with the id alone", async () => {
		answer = () => Promise.reject(new OutboundUnavailable("timeout"));
		const app = await boot();
		await app.find();
		expect(app.lines()).toEqual([
			{ level: "warn", event: "clients-cimd.fetch_failed", fields: { client: id } },
		]);
	});

	it("never brings back an expired document", async () => {
		answer = () => json(document, { "cache-control": "max-age=30" });
		const app = await boot();
		expect(await app.find()).toBeDefined();
		now += 29_999;
		expect(await app.find()).toBeDefined();
		expect(sent).toHaveLength(1);
		now += 1;
		answer = () => Promise.reject(new OutboundUnavailable("timeout"));
		expect(await app.find()).toBeUndefined();
	});

	it.each(["no-store", "no-cache"])("is not kept when the answer says %s", async (directive) => {
		answer = () => json(document, { "cache-control": directive });
		const app = await boot();
		await app.find();
		await app.find();
		expect(sent).toHaveLength(2);
	});

	it("is kept for the cache time when the max age is not a count of seconds", async () => {
		answer = () => json(document, { "cache-control": "max-age=1.5" });
		const app = await boot();
		await app.find();
		now += 599_999;
		expect(await app.find()).toBeDefined();
		expect(sent).toHaveLength(1);
	});
});

describe("clients-cimd: the operator's section", () => {
	it.each([
		["an allow entry with a wildcard", { allow: ["*.app.example"] }, "clients-cimd.allow.0"],
		["a deny entry with a port", { deny: ["app.example:443"] }, "clients-cimd.deny.0"],
		["an address", { deny: ["192.0.2.1"] }, "clients-cimd.deny.0"],
		["an IPv6 address", { allow: ["[::1]"] }, "clients-cimd.allow.0"],
		["a short IPv4 form", { deny: ["10.5"] }, "clients-cimd.deny.0"],
		["a trailing dot", { allow: ["app.example."] }, "clients-cimd.allow.0"],
		["an underscore", { allow: ["app_x.example"] }, "clients-cimd.allow.0"],
		["a label led by a hyphen", { allow: ["-app.example"] }, "clients-cimd.allow.0"],
		["a label ended by a hyphen", { deny: [".app-.example"] }, "clients-cimd.deny.0"],
		[
			"a label past 63 characters",
			{ allow: [`${"a".repeat(64)}.example`] },
			"clients-cimd.allow.0",
		],
		[
			"offline_access in the ceiling",
			{ scopes: ["openid", "offline_access"] },
			"clients-cimd.scopes.1",
		],
		["a size of zero", { "max-size": "0B" }, "clients-cimd.max-size"],
		["no concurrency", { "max-concurrent": 0 }, "clients-cimd.max-concurrent"],
	])("refuses boot for %s", async (_, settings, where) => {
		const error = await boot(settings).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(BootRefused);
		expect((error as BootRefused).refusals.map((r) => r.where)).toContain(where);
	});

	it("refuses boot where the size or the timeout is above outbound's cap, naming the key and no value", async () => {
		const caps = { maxBytes: 4096, timeoutMs: 1000 };
		const error = await boot({ "max-size": "5KiB", timeout: "2s" }, { caps }).catch(
			(e: unknown) => e,
		);
		expect(error).toBeInstanceOf(BootRefused);
		const refusals = (error as BootRefused).refusals;
		expect(refusals.map((r) => r.where)).toEqual(["clients-cimd.max-size", "clients-cimd.timeout"]);
		expect(refusals.map((r) => r.reason)).toEqual([
			"is above outbound's cap: lower it, or raise outbound.max-response-size",
			"is above outbound's cap: lower it, or raise outbound.timeout",
		]);
		expect(JSON.stringify(refusals)).not.toMatch(/4096|5120|1000|2000/);
	});

	it("refuses boot where outbound gives a metadata document's names no lookup, naming what gives them one", async () => {
		const error = await boot({}, { lookups: 0 }).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(BootRefused);
		expect((error as BootRefused).refusals).toEqual([
			{
				where: "clients-cimd",
				reason:
					"outbound resolves no name a metadata document chooses: set outbound.max-lookups to 2 or more (and, resolving in process, UV_THREADPOOL_SIZE to 4 or more)",
			},
		]);
		await expect(boot({}, { lookups: 1 })).resolves.toBeDefined();
	});

	it("refuses boot where the operator names no document host and does not take any [rfc9700-4.11.2-c]", async () => {
		for (const settings of [{ "allow-any-host": false }, { allow: [] }]) {
			const error = await boot(settings).catch((e: unknown) => e);
			expect(error, JSON.stringify(settings)).toBeInstanceOf(BootRefused);
			expect((error as BootRefused).refusals).toEqual([
				{
					where: "clients-cimd.allow",
					reason:
						"is empty: name the hosts a client id's document may come from, or set clients-cimd.allow-any-host",
				},
			]);
		}
	});

	it("takes any host deny leaves where allow-any-host is set, warning at every start, and never beside allow", async () => {
		const any = await boot({ "allow-any-host": true });
		expect(any.warned()).toEqual([
			{ level: "warn", event: "clients-cimd.any_host_allowed", fields: {} },
		]);
		expect(await any.find()).toMatchObject({ id });
		expect(sent.map((one) => one.narrower?.hosts)).toEqual([undefined]);
		expect((await boot({ allow: ["app.example"] })).warned()).toEqual([]);
		const error = await boot({ "allow-any-host": true, allow: ["app.example"] }).catch(
			(e: unknown) => e,
		);
		expect(error).toBeInstanceOf(BootRefused);
		expect((error as BootRefused).refusals).toEqual([
			{ where: "clients-cimd.allow-any-host", reason: "is set beside allow: keep one of them" },
		]);
	});

	it("boots with the size and the timeout at outbound's cap or below it", async () => {
		const caps = { maxBytes: 5120, timeoutMs: 5000 };
		await expect(boot({}, { caps })).resolves.toBeDefined();
		await expect(boot({ "max-size": "1KiB", timeout: "1s" }, { caps })).resolves.toBeDefined();
	});

	it("takes host names, one beyond ASCII by its punycode, as outbound's hosts", async () => {
		const allow = ["Bücher.example", "app", ".corp.example"];
		const app = await boot({ allow });
		await app.find("https://xn--bcher-kva.example/c");
		expect(sent[0]?.narrower?.hosts).toEqual(allow);
	});

	it("keeps at most the cache entries", async () => {
		answer = (url) => json({ ...document, client_id: url });
		const app = await boot({ "cache-entries": 1 });
		await app.find();
		await app.find("https://app.example/other.json");
		await app.find();
		expect(sent).toHaveLength(3);
	});

	it("runs at most the concurrent fetches, the one past them none at once", async () => {
		const { promise, resolve } = Promise.withResolvers<OutboundResponse>();
		answer = () => promise;
		const app = await boot({ "max-concurrent": 1 });
		const first = app.find();
		expect(await app.find("https://app.example/other.json")).toBeUndefined();
		expect(sent).toHaveLength(1);
		resolve(json(document));
		expect(await first).toBeDefined();
	});

	it("narrows outbound by its own size and time, its destinations marked an outside party's choice", async () => {
		await (await boot({ "max-size": "100B", timeout: "50ms" })).find();
		expect(sent[0]?.narrower).toEqual({ maxBytes: 100, timeoutMs: 50, outsideChosen: true });
	});
});

describe("clients-cimd: times and sizes in the section", () => {
	/** Each key of a time or a size, with what a bare number of it and digits alone are refused as. */
	const unitKeys = [
		["max-size", "written with its unit, such as 64KiB", "byte size must name its unit"],
		["timeout", "written with its unit, such as 30s", "duration must name its unit"],
		["cache-lifetime", "written with its unit, such as 30s", "duration must name its unit"],
		["refused-lifetime", "written with its unit, such as 30s", "duration must name its unit"],
	] as const;

	it("reads a time or a size as an operator writes it, with a unit", () => {
		const read = section.parse({
			"max-size": "64KiB",
			timeout: "2s",
			"cache-lifetime": "5m",
			"refused-lifetime": "30s",
		});
		expect(read).toMatchObject({
			"max-size": 65_536,
			timeout: 2000,
			"cache-lifetime": 300,
			"refused-lifetime": 30,
		});
	});

	it("keeps a document for the cache lifetime and a refusal for the refused lifetime it reads", async () => {
		const app = await boot({ "cache-lifetime": "2m", "refused-lifetime": "10s" });
		await app.find();
		now += 119_999;
		await app.find();
		expect(sent).toHaveLength(1);
		now += 1;
		answer = () => json(document, {}, 404);
		await app.find();
		now += 9_999;
		await app.find();
		expect(sent).toHaveLength(2);
		now += 1;
		await app.find();
		expect(sent).toHaveLength(3);
	});

	it.each(unitKeys)(
		"refuses boot for %s written as a bare number or digits alone",
		async (key, bare, digits) => {
			for (const [written, reason] of [
				[5, bare],
				["5", digits],
			] as const) {
				const error = await boot({ [key]: written }).catch((e: unknown) => e);
				expect(error, String(written)).toBeInstanceOf(BootRefused);
				expect((error as BootRefused).refusals, String(written)).toContainEqual(
					expect.objectContaining({ where: `clients-cimd.${key}`, reason }),
				);
			}
			expect(section.safeParse({ [key]: "5" }).error?.issues).toMatchObject([
				{ path: [key], params: { problem: "missing-unit" } },
			]);
		},
	);

	it("reads an empty section with the defaults it had", () => {
		expect(section.parse({})).toEqual({
			allow: [],
			"allow-any-host": false,
			deny: [],
			scopes: [],
			audiences: [],
			"max-size": 5120,
			timeout: 5000,
			"cache-lifetime": 600,
			"cache-entries": 256,
			"refused-lifetime": 60,
			"max-concurrent": 8,
		});
	});
});

it("takes all it names, the code grant composed or not", async () => {
	for (const code of [true, false]) {
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect(
			(await takesUnused((await boot({}, { code })).input))["clients-cimd"],
			`code ${code}`,
		).toBeUndefined();
	}
});
