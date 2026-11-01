import { Unavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import {
	DestinationRefused,
	jsonObjectOf,
	type Narrower,
	type Outbound,
	type OutboundRequest,
	OutboundUnavailable,
	postJson,
	sendFailureOf,
} from "../../contract.ts";

const answer = (status: number, text: string) => ({
	status,
	headers: new Map<string, string>(),
	body: new TextEncoder().encode(text),
});

it("reads one JSON object from a 200 answer, frozen, and tells any other answer apart by its status", () => {
	const read = jsonObjectOf(answer(200, '{"keys":[{"kid":"a"}]}'));
	expect(read).toEqual({ kind: "object", value: { keys: [{ kid: "a" }] } });
	if (read.kind !== "object") throw new Error(read.kind);
	expect(Object.isFrozen((read.value.keys as object[])[0])).toBe(true);
	expect(jsonObjectOf(answer(404, '{"a":1}'))).toEqual({ kind: "other", status: 404 });
	for (const text of ["{nope", "[1]", "null", '"x"', ""]) {
		expect(jsonObjectOf(answer(200, text)), text).toEqual({ kind: "other", status: 200 });
	}
	// Bytes that are not UTF-8 are not JSON, rather than read with replacement characters.
	const malformed = {
		...answer(200, ""),
		body: Uint8Array.of(0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d),
	};
	expect(jsonObjectOf(malformed)).toEqual({ kind: "other", status: 200 });
});

it("reads an answer of another status only when the caller names that status", () => {
	const refused = answer(400, '{"error":"invalid_grant"}');
	expect(jsonObjectOf(refused)).toEqual({ kind: "other", status: 400 });
	expect(jsonObjectOf(refused, 400)).toEqual({ kind: "object", value: { error: "invalid_grant" } });
	expect(jsonObjectOf(answer(200, '{"a":1}'), 400)).toEqual({ kind: "other", status: 200 });
	expect(jsonObjectOf(answer(400, "[1]"), 400)).toEqual({ kind: "other", status: 400 });
});

it("names a send's failure by the refusal's reason or outbound's failure, and anything else no-answer", () => {
	expect(sendFailureOf(new DestinationRefused("special-address"))).toBe("special-address");
	expect(sendFailureOf(new OutboundUnavailable("timeout"))).toBe("timeout");
	for (const other of [new Error("bug"), new Unavailable("ledger"), "x", undefined]) {
		expect(sendFailureOf(other)).toBe("no-answer");
	}
});

it("posts JSON asking JSON, the credential a Bearer token or as given in the header named, and throws what failed makes of a send that fails", async () => {
	const sent: [string, OutboundRequest | undefined, Narrower | undefined][] = [];
	let fails: unknown;
	const out: Outbound = {
		fetch: async (url, request, narrower) => {
			sent.push([url, request, narrower]);
			if (fails !== undefined) throw fails;
			return answer(204, "");
		},
	};
	const failed = (reason: string) => new Error(`failed: ${reason}`);
	const narrower: Narrower = { maxBytes: 64 };
	const url = "https://ledger.example/spend";
	expect(
		(await postJson(out, { url, body: { a: 1 }, credential: "t", narrower }, failed)).status,
	).toBe(204);
	await postJson(out, { url, body: [], credential: "t", credentialHeader: "x-token" }, failed);
	await postJson(out, { url, body: {} }, failed);
	const json = { accept: "application/json", "content-type": "application/json" };
	expect(sent).toEqual([
		[url, { method: "POST", headers: json, body: '{"a":1}', credential: "Bearer t" }, narrower],
		[
			url,
			{ method: "POST", headers: json, body: "[]", credential: "t", credentialHeader: "x-token" },
			undefined,
		],
		[url, { method: "POST", headers: json, body: "{}" }, undefined],
	]);
	fails = new OutboundUnavailable("busy");
	await expect(postJson(out, { url, body: {} }, failed)).rejects.toThrow("failed: busy");
});
