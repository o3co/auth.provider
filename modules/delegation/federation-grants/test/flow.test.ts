import { csrfChecked } from "@mod/csrf";
import { requestsPerSource } from "@mod/rate-limit";
import { describe, expect, it } from "vitest";
import { back, harness, origin, scopes, upstreamLogin, upstreamTokens } from "./harness.ts";

describe("connecting a grant", () => {
	it("lodges an intent, asks the user, starts the upstream and activates on its return", async () => {
		const h = await harness();
		const flow = await h.started();
		expect(flow.lodged.status).toBe(201);
		expect(flow.lodged.json).toMatchObject({
			status: "pending",
			connect_expires_in: 600,
			expires_in: 2_592_000,
		});
		expect(String(flow.lodged.json?.connect_uri)).toMatch(
			`${origin}/session/federation-grants/connect?request=`,
		);
		// An answered question is no longer asked.
		expect((await h.intents.asked(flow.challenge)).kind).toBe("invalid");
		const start = h.asked.starts[0];
		expect(start).toMatchObject({
			scopes,
			challengeMethod: "S256",
			redirectUri: `${origin}/session/federation-grants/callback/cal`,
		});
		const done = await h.callback(flow.state, flow.browser);
		expect(done.status).toBe(303);
		expect(done.headers.location).toBe(`${back}?grant_id=${flow.id}&state=st`);
		const token = await h.grantCall(flow.id, "token");
		expect(token).toMatchObject({
			status: 200,
			json: { access_token: "up-1", token_type: "Bearer", scope: scopes.join(" ") },
		});
		expect((await h.grantCall(flow.id, "status")).json).toMatchObject({
			status: "active",
			upstream: { subject: "u-alice" },
		});
		expect(h.events.map((e) => e.kind)).toContain("federation.grant.authorized");
	});

	it("holds the answer to the CSRF policy", async () => {
		const h = await harness();
		const answer = h.routes.find(
			(r) => r.method === "POST" && r.path === "/session/federation-grants/consent",
		);
		expect(answer?.uses?.map((u) => u.policy)).toContain(csrfChecked);
	});

	it("checks the consent's CSRF evidence before it counts the source, so another site's post spends no count", async () => {
		const h = await harness();
		const answer = h.routes.find(
			(r) => r.method === "POST" && r.path === "/session/federation-grants/consent",
		);
		expect(answer?.uses?.map((u) => u.policy)).toEqual([csrfChecked, requestsPerSource]);
	});

	it("reads each part of the upstream's tokens once, refusing a part that throws", async () => {
		const h = await harness();
		let reads = 0;
		const tokens = upstreamTokens();
		const once = Object.defineProperty({ ...tokens }, "accessToken", {
			get: () => {
				reads++;
				if (reads > 1) throw new Error("read twice");
				return "up-once";
			},
		});
		h.script.exchange = async () => upstreamLogin(once);
		const flow = await h.started();
		await h.callback(flow.state, flow.browser);
		expect((await h.grantCall(flow.id, "token")).json?.access_token).toBe("up-once");
		expect(reads).toBe(1);
	});
});
