import type { AuditRecord } from "@mod/audit";
import type { Client, Section } from "@mod/clients";
import { listening, routes } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { redirectsFor } from "@mod/redirect-uris/testing";
import { describe, expect, it } from "vitest";
import { type Decision, recorded as refused } from "../../decision.ts";
import { routeWith } from "../route.ts";

const callback = "https://app.example/cb";
const sections: Record<string, unknown> = redirectsFor([callback]);
const nocode: Client = {
	id: "nocode",
	kind: "confidential",
	method: "client_secret_post",
	registered: true,
	section: <T>(section: Section<T>) =>
		(section.schema["~standard"].validate(sections[section.name]) as { value: T }).value,
};

/** The route over a flow that refuses the client a recorded refusal, as one without the code grant. */
function route(
	flow: () => Promise<Decision> = async () =>
		refused("unauthorized_client", "grant_type_not_allowed"),
	find = async (id: string) => (id === nocode.id ? nocode : undefined),
) {
	const recorded: AuditRecord[] = [];
	const logged = recordingLog();
	const declared = routeWith({
		issuer: "https://as.example",
		self: "https://as.example/oauth/authorize",
		clients: { find },
		audit: { record: (event: AuditRecord) => void recorded.push(event) },
		flow,
		log: logged.log,
		// No rule composed: a repeated parameter is a malformed request.
		rule: {},
	});
	return { answer: declared.handle, declared, recorded, lines: logged.lines };
}

const query = new Map([
	["response_type", ["code"]],
	["client_id", ["nocode"]],
	["redirect_uri", [callback]],
]);

it("records the request's source only when http determined it", async () => {
	const { answer, recorded } = route();
	const known = await answer(testRequest({ query, source: { address: "198.51.100.7" } }));
	const unknown = await answer(
		testRequest({ query, source: { address: "10.0.0.1", determined: false } }),
	);
	expect([known.status, unknown.status]).toEqual([302, 302]);
	expect(recorded.map((event) => event.attributes)).toEqual([
		{ client: "nocode", reason: "grant_type_not_allowed", source: "198.51.100.7" },
		{ client: "nocode", reason: "grant_type_not_allowed" },
	]);
});

it("answers Unavailable once the redirect URI is trusted by sending temporarily_unavailable back, warning what and the route", async () => {
	const after = route(async (): Promise<never> => {
		throw new Unavailable("reauth store");
	});
	const sent = await after.answer(testRequest({ query }));
	expect([sent.status, new URL(sent.headers?.location ?? "").searchParams.get("error")]).toEqual([
		302,
		"temporarily_unavailable",
	]);
	expect(after.lines()).toEqual([
		{
			level: "warn",
			event: "authorize.unavailable",
			fields: { what: "reauth store", route: "/oauth/authorize" },
		},
	]);
	expect(after.recorded).toEqual([]);
});

it("leaves Unavailable before the redirect URI is trusted to http, which answers 503 temporarily_unavailable and warns once", async () => {
	const before = route(undefined, async (): Promise<never> => {
		throw new Unavailable("clients");
	});
	const logged = recordingLog();
	const app = await assemble({
		modules: [
			http,
			defineModule({ name: "authorize-route", takes: [] }, (m) => [
				m.contribute(routes).by(() => ({
					method: "GET",
					path: "/oauth/authorize",
					changesState: true,
					crossSite: "a test route",
					unlimited: "a test route",
					...before.declared,
				})),
			]),
		],
		config: { ...kernelConfig(), ...httpConfig() },
		runtime: quietRuntime({ log: logged.log }),
	});
	await app.start();
	try {
		const res = await fetch(
			`http://127.0.0.1:${app.get(listening).port()}/oauth/authorize?client_id=nocode`,
		);
		expect([res.status, await res.json()]).toEqual([503, { error: "temporarily_unavailable" }]);
	} finally {
		await app.stop(1000);
	}
	expect([...before.lines(), ...logged.lines().filter((line) => line.level === "warn")]).toEqual([
		{
			level: "warn",
			event: "http.unavailable",
			fields: { what: "clients", route: "/oauth/authorize" },
		},
	]);
	expect(before.recorded).toEqual([]);
});

describe("route: an OpenID Connect request", () => {
	/** A client that registered no redirect URI. */
	const bare: Client = { ...nocode, id: "bare", section: <T>() => ({ "redirect-uris": [] }) as T };
	const find = async (id: string) => ({ nocode, bare })[id as "nocode" | "bare"];
	const issued = route(async () => ({ kind: "code", code: "c1", subject: "alice" }), find);
	/** The query an OpenID request sends, with these values set and those named in `left` left out. */
	const oidc = (extra: Record<string, string> = {}, ...left: string[]) => {
		const sent = new Map([...query, ["scope", ["openid read"]], ["state", ["s1"]]]);
		for (const [name, value] of Object.entries(extra)) sent.set(name, [value]);
		for (const name of left) sent.delete(name);
		return sent;
	};
	/** Where an answer sends the browser, and the code, error, state and iss it carries. */
	const sentBack = async (answer: typeof issued.answer, sent: Map<string, string[]>) => {
		const res = await answer(testRequest({ query: sent }));
		const at = new URL(res.headers?.location ?? "");
		const carried = ["code", "error", "state", "iss"].map((n) => at.searchParams.get(n));
		return [res.status, `${at.origin}${at.pathname}`, ...carried];
	};

	it("answers one without a client or a registered redirect URI locally, never sending it on [oidc-core-3.1.2.1-d] [oidc-core-3.1.2.1-e] [oidc-core-3.1.2.2-c] [rfc6749-3.1.2.2-a] [rfc6749-3.1.2.2-b]", async () => {
		for (const sent of [
			oidc({}, "client_id"),
			oidc({ client_id: "" }),
			oidc({}, "redirect_uri"),
			oidc({ redirect_uri: "" }),
			oidc({ client_id: "bare" }),
			oidc({ client_id: "bare", redirect_uri: "http://127.0.0.1:9000/cb" }),
		]) {
			const res = await issued.answer(testRequest({ query: sent }));
			expect([res.status, res.headers?.location], JSON.stringify([...sent])).toEqual([
				400,
				undefined,
			]);
		}
	});

	it("sends its code, and every refusal once the redirect URI is trusted, back to it by 302 with state and iss [oidc-core-3.1.2.2-i] [oidc-core-16.22-a]", async () => {
		const refused = (error: string) => [302, callback, null, error, "s1", "https://as.example"];
		expect(await sentBack(issued.answer, oidc())).toEqual([
			302,
			callback,
			"c1",
			null,
			"s1",
			"https://as.example",
		]);
		expect(await sentBack(route(undefined, find).answer, oidc())).toEqual(
			refused("unauthorized_client"),
		);
		const repeated = oidc();
		repeated.set("nonce", ["n1", "n2"]);
		expect(await sentBack(issued.answer, repeated)).toEqual(refused("invalid_request"));
		expect(await sentBack(issued.answer, oidc({ nonce: "n".repeat(2049) }))).toEqual(
			refused("invalid_request"),
		);
	});

	it("puts no token in what it sends back, a code or a refusal, in the query alone [oidc-core-16.4-a]", async () => {
		const told = ["code", "state", "iss", "error", "error_description"];
		for (const res of [
			await issued.answer(testRequest({ query: oidc() })),
			await route(undefined, find).answer(testRequest({ query: oidc() })),
		]) {
			const at = new URL(res.headers?.location ?? "");
			expect(at.hash).toBe("");
			for (const name of at.searchParams.keys()) expect(told).toContain(name);
			expect(at.searchParams.has("access_token") || at.searchParams.has("id_token")).toBe(false);
		}
	});

	it("sends a state holding reserved characters back as the one value it was sent [rfc6749-10.14-a]", async () => {
		const state = "a&b=c#d%25e+f g/?";
		const res = await issued.answer(testRequest({ query: oidc({ state }) }));
		const at = new URL(res.headers?.location ?? "");
		expect([at.hash, at.searchParams.getAll("state"), at.searchParams.get("code")]).toEqual([
			"",
			[state],
			"c1",
		]);
	});

	it("takes one by POST as by GET, sending it on to the same GET by 303 [oidc-core-3.1.2.1-a]", async () => {
		const sent = oidc();
		const res = await issued.answer(testRequest({ method: "POST", form: sent }));
		expect(res.status).toBe(303);
		const at = new URL(res.headers?.location ?? "");
		expect(`${at.origin}${at.pathname}`).toBe("https://as.example/oauth/authorize");
		const again = new Map([...at.searchParams].map(([k, v]) => [k, [v]]));
		expect(again).toEqual(sent);
		expect((await sentBack(issued.answer, again))[2]).toBe("c1");
	});
});
