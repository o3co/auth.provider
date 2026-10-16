import { type EndSessionReturn, upstreamEndSessions } from "@mod/federation-tokens";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { type UpstreamEnd, upstreamEnds } from "@mod/rp-logout";
import { expect, it } from "vitest";
import bridge from "../src/module.ts";

const logged = recordingLog();
const runtime = quietRuntime({ log: logged.log });
const seen = contract<readonly UpstreamEnd[]>("test.seen");
const reader = defineModule({ name: "reader" }, (m) => [
	m.provide(seen).by((c) => c.collect(upstreamEnds)),
]);

it("asks federation-tokens for the end of session, carrying the session, the return and state", async () => {
	const asked: [string, EndSessionReturn][] = [];
	const ends = defineModule({ name: "federation-tokens" }, (m) => [
		m.provide(upstreamEndSessions).by(() => ({
			of: async (session, back) => {
				asked.push([session, back]);
				return "https://idp.example/logout";
			},
		})),
	]);
	const app = await assemble({ modules: [ends, bridge, reader], config: kernelConfig(), runtime });
	const [end] = app.get(seen);
	const back = { postLogoutRedirectUri: "https://rp.example/after", state: "s" };
	expect(await end?.at("s-1", back)).toBe("https://idp.example/logout");
	expect(asked).toEqual([["s-1", back]]);
});

it("answers none when federation-tokens cannot tell, and logs the type of what it threw, not the session", async () => {
	const ends = defineModule({ name: "federation-tokens" }, (m) => [
		m.provide(upstreamEndSessions).by(() => ({
			of: async (session) => {
				if (session === "s-1") throw new Error("store down");
				throw "store down";
			},
		})),
	]);
	const app = await assemble({ modules: [ends, bridge, reader], config: kernelConfig(), runtime });
	const [end] = app.get(seen);
	const from = logged.lines().length;
	expect(await end?.at("s-1", {})).toBeUndefined();
	expect(await end?.at("s-2", {})).toBeUndefined();
	expect(logged.lines().slice(from)).toEqual([
		{ level: "warn", event: "rp-logout-federation.end_failed", fields: { error: "Error" } },
		{ level: "warn", event: "rp-logout-federation.end_failed", fields: { error: "string" } },
	]);
});

it("refuses to start without federation-tokens", async () => {
	await expect(
		assemble({ modules: [bridge, reader], config: kernelConfig(), runtime }),
	).rejects.toMatchObject({
		refusals: [
			{
				where: "rp-logout-federation",
				reason: `no module provides ${upstreamEndSessions.label}`,
			},
		],
	});
});
