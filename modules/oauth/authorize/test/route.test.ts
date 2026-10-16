import type { AuditRecord } from "@mod/audit";
import type { Client, Section } from "@mod/clients";
import { testRequest } from "@mod/http/testing";
import { Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { type Decision, recorded as refused } from "../src/decision.ts";
import { routeWith } from "../src/route/route.ts";
import { redirectsFor } from "../src/testing.ts";

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
	const answer = routeWith({
		issuer: "https://as.example",
		self: "https://as.example/oauth/authorize",
		clients: { find },
		audit: { record: (event: AuditRecord) => void recorded.push(event) },
		flow,
		log: logged.log,
		// No rule composed: a repeated parameter is a malformed request.
		rule: {},
	});
	return { answer, recorded, lines: logged.lines };
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

it("leaves one warning naming what was unavailable and the route, before the redirect URI is trusted and after", async () => {
	const down = async (): Promise<never> => {
		throw new Unavailable("reauth store");
	};
	const after = route(down);
	const sent = await after.answer(testRequest({ query }));
	const before = route(undefined, down);
	const local = await before.answer(testRequest({ query }));
	expect([sent.status, new URL(sent.headers?.location ?? "").searchParams.get("error")]).toEqual([
		302,
		"temporarily_unavailable",
	]);
	expect(local.status).toBe(503);
	const warned = { level: "warn", event: "authorize.unavailable" };
	expect([...after.lines(), ...before.lines()]).toEqual([
		{ ...warned, fields: { what: "reauth store", route: "/oauth/authorize" } },
		{ ...warned, fields: { what: "reauth store", route: "/oauth/authorize" } },
	]);
	expect([after.recorded, before.recorded]).toEqual([[], []]);
});
