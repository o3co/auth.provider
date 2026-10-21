import { testRequest } from "@mod/http/testing";
import { expect, it } from "vitest";
import { back, harness, said } from "../../../test/harness.ts";

it("records a client route's refused client authentication through clients, by its reason alone, and nothing for a known public client", async () => {
	const h = await harness();
	const from = h.events.length;
	const path = "/oauth/federation-grants";
	const json = { connection: "cal", sub: "alice", redirect_uri: back, state: "s" };
	const basic = `Basic ${Buffer.from("worker:nope").toString("base64")}`;
	const headers = new Map([["authorization", basic]]);
	expect(said(await h.send(testRequest({ method: "POST", path, json, headers })))).toBe(
		"401 invalid_client",
	);
	const spa = { ...json, client_id: "spa" };
	expect(said(await h.send(testRequest({ method: "POST", path, json: spa })))).toBe(
		"401 invalid_client",
	);
	expect(h.events.slice(from).map(({ kind, attributes }) => [kind, attributes])).toEqual([
		["client.authentication.failure", { source: "127.0.0.1", reason: "bad_credentials" }],
	]);
});
