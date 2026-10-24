import type { AuditRecord } from "@mod/audit";
import type { Client, Section } from "@mod/clients";
import { listening, routes } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { redirectsFor } from "@mod/redirect-uris/testing";
import { expect, it } from "vitest";
import { type Decision, recorded as refused } from "../src/decision.ts";
import { routeWith } from "../src/route/route.ts";

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
