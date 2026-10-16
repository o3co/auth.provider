import { Unavailable } from "@mod/kernel";
import {
	DestinationRefused,
	type OutboundRequest,
	type SignedNarrower,
	type SignedOutbound,
} from "@mod/outbound";
import { expect, it } from "vitest";
import { sourcesOver } from "../src/sources.ts";

function outboundAnswering(answer: () => Promise<number>) {
	const sent: { url: string; request: OutboundRequest; narrower: SignedNarrower }[] = [];
	const outbound: SignedOutbound = {
		fetch: async (url, request, narrower) => {
			sent.push({ url, request, narrower });
			const status = await answer();
			return { status, headers: new Map(), body: new Uint8Array([status % 256]) };
		},
	};
	return { outbound, sent };
}

const runtime = { now: () => 5, random: (n: number) => new Uint8Array(n) };
const reach = { hosts: ["ca.example"], timeoutMs: 3000 };

it("gets a CRL and posts an OCSP request, within the hosts and time it is given", async () => {
	const { outbound, sent } = outboundAnswering(async () => 200);
	const sources = sourcesOver(outbound, reach, runtime);
	expect(await sources.fetch("http://ca.example/crl")).toEqual({
		kind: "material",
		body: new Uint8Array([200]),
	});
	await sources.fetch("http://ca.example/ocsp", new Uint8Array([1]));
	expect(sent).toEqual([
		{ url: "http://ca.example/crl", request: { method: "GET" }, narrower: reach },
		{
			url: "http://ca.example/ocsp",
			request: {
				method: "POST",
				headers: {
					"content-type": "application/ocsp-request",
					accept: "application/ocsp-response",
				},
				body: new Uint8Array([1]),
			},
			narrower: reach,
		},
	]);
	expect([sources.now(), sources.random(2)]).toEqual([5, new Uint8Array(2)]);
});

it("takes a server failing, busy or timed out, or no answer in time, as an outage, and anything else not given as a refusal", async () => {
	const kindOf = async (answer: () => Promise<number>) =>
		(await sourcesOver(outboundAnswering(answer).outbound, reach, runtime).fetch("http://x/")).kind;
	expect(await kindOf(async () => 500)).toBe("outage");
	expect(await kindOf(async () => 599)).toBe("outage");
	expect(await kindOf(async () => 429)).toBe("outage");
	expect(await kindOf(async () => 408)).toBe("outage");
	expect(await kindOf(async () => 400)).toBe("refused");
	expect(await kindOf(async () => 404)).toBe("refused");
	expect(await kindOf(async () => 304)).toBe("refused");
	expect(await kindOf(async () => 600)).toBe("refused");
	expect(
		await kindOf(async () => {
			throw new Unavailable("outbound");
		}),
	).toBe("outage");
	expect(
		await kindOf(async () => {
			throw new DestinationRefused("not-allowed");
		}),
	).toBe("refused");
	await expect(
		kindOf(async () => {
			throw new TypeError("a fault");
		}),
	).rejects.toBeInstanceOf(TypeError);
});
