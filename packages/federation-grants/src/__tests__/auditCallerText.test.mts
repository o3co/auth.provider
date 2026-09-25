/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * What the audit trail keeps of a caller's own text (#593, D18).
 *
 * Two fields of these events are the caller's before anything has checked
 * them: `details.grantId`, the path parameter — audited by the denial hook
 * before client authentication, and by core for a grant nobody holds — and
 * `subject`, the `sub` the body asserts. The deployment's sink is read by
 * systems that split on a line break (the standalone writes every event into
 * its log), so both reach it sanitised and capped, as the log lines of this
 * package already carry them. Run against the real router, stores and core
 * retrieval, with the real sink seam.
 */

import type { AuditEvent } from "@o3co/auth-provider-core";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { basic, CLIENT_ID, connection, GRANT_ID, harness, REDIRECT_URI } from "./harness.mjs";

/** A line break, a terminal escape, a NUL and a bell, then 10 000 characters. */
const HOSTILE = `g\r\nFORGED federation.grant.token.success\u001b[31m\u0000\u0007${"x".repeat(10_000)}`;

// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be audited.
const CONTROL = /[\u0000-\u001f\u007f]/;

/** What an assertion needs of an audited value: a failure prints this, not the value. */
const shapeOf = (value: unknown) => ({
	string: typeof value === "string",
	control: CONTROL.test(String(value)),
	within200: String(value).length <= 200,
	head: String(value).slice(0, 9),
});
const BOUNDED = { string: true, control: false, within200: true, head: "g??FORGED" };

/** The one event of `type` the sink was told about. */
const onlyEvent = (events: readonly AuditEvent[], type: string): AuditEvent => {
	const matching = events.filter((event) => event.type === type);
	expect(matching).toHaveLength(1);
	return matching[0] as AuditEvent;
};

const grantIdOf = (event: AuditEvent): unknown =>
	(event.details as { grantId?: unknown } | undefined)?.grantId;

describe("the audit trail — a caller's grant id and subject, sanitised and capped", () => {
	it("audits a refused credential's path grant id bounded (the denial hook, before authentication)", async () => {
		const h = harness();

		const response = await request(h.app)
			.post(`/oauth/federation-grants/${encodeURIComponent(HOSTILE)}/token`)
			.set("Authorization", basic(CLIENT_ID, "wrong"))
			.send({ sub: "local-subject" });

		expect(response.status).toBe(401);
		await h.background.drain();
		expect(shapeOf(grantIdOf(onlyEvent(h.events, "federation.grant.token.denied")))).toEqual(
			BOUNDED,
		);
	});

	it("audits an unknown grant's path id and asserted subject bounded (core's denial)", async () => {
		const h = harness();

		const response = await request(h.app)
			.post(`/oauth/federation-grants/${encodeURIComponent(HOSTILE)}/token`)
			.set("Authorization", basic())
			.send({ sub: HOSTILE });

		expect(response.status).toBe(404);
		await h.background.drain();
		const event = onlyEvent(h.events, "federation.grant.token.denied");
		expect(shapeOf(grantIdOf(event))).toEqual(BOUNDED);
		expect(shapeOf(event.subject)).toEqual(BOUNDED);
	});

	it("audits a refused withdrawal's asserted subject bounded", async () => {
		const h = harness();
		await h.seed();

		const response = await request(h.app)
			.post(`/oauth/federation-grants/${GRANT_ID}/revoke`)
			.set("Authorization", basic())
			.send({ sub: HOSTILE });

		expect(response.status).toBe(404);
		await h.background.drain();
		expect(shapeOf(onlyEvent(h.events, "federation.grant.revoke.denied").subject)).toEqual(BOUNDED);
	});

	it("audits a lodged intent's asserted subject bounded", async () => {
		// Asserted, not yet proven — the connect flow is where a session
		// establishes whose grant it is — and still the caller's text.
		const h = harness();

		const response = await request(h.app)
			.post("/oauth/federation-grants")
			.set("Authorization", basic())
			.send({
				connection: connection.name,
				sub: HOSTILE,
				redirect_uri: REDIRECT_URI,
				state: "client-state-1",
			});

		expect(response.status).toBe(201);
		await h.background.drain();
		expect(shapeOf(onlyEvent(h.events, "federation.grant.requested").subject)).toEqual(BOUNDED);
	});

	describe("the event's ip and user agent", () => {
		// Behind `trust proxy`, `req.ip` is what the caller wrote in
		// X-Forwarded-For. Over real HTTP it and the user agent can carry a tab,
		// the C1 controls (U+0085 NEL, U+009B CSI) and ten thousand characters.
		// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be audited.
		const REQUEST_CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
		const requestShapeOf = (value: unknown) => ({
			string: typeof value === "string",
			control: REQUEST_CONTROL.test(String(value)),
			within200: String(value).length <= 200,
			kept: /^x\?+FORGED /.test(String(value)),
		});
		const REQUEST_BOUNDED = { string: true, control: false, within200: true, kept: true };
		const REQUEST_HOSTILE = `x\t\u0085\u009bFORGED federation.grant ${"h".repeat(10_000)}`;

		/** The denial a refused credential audits, through the route's own bridge. */
		const deniedEvent = async (headers: Record<string, string>): Promise<AuditEvent> => {
			const h = harness();
			h.app.set("trust proxy", true);

			const response = await request(h.app)
				.post(`/oauth/federation-grants/${GRANT_ID}/token`)
				.set("Authorization", basic(CLIENT_ID, "wrong"))
				.set(headers)
				.send({ sub: "local-subject" });

			expect(response.status).toBe(401);
			await h.background.drain();
			return onlyEvent(h.events, "federation.grant.token.denied");
		};

		it.each([
			["a hostile value: no ip", REQUEST_HOSTILE, undefined],
			["x: no ip", "x", undefined],
			["a link-local address with a zone: the address alone", "fe80::1%eth0", "fe80::1"],
		])("audits an X-Forwarded-For of %s", async (_label, forwarded, expected) => {
			const event = await deniedEvent({ "X-Forwarded-For": forwarded });
			expect({ ip: event.ip, hasIp: "ip" in event }).toEqual({
				ip: expected,
				hasIp: expected !== undefined,
			});
		});

		it("audits a user agent sanitised and capped", async () => {
			expect(
				requestShapeOf((await deniedEvent({ "User-Agent": REQUEST_HOSTILE })).userAgent),
			).toEqual(REQUEST_BOUNDED);
		});
	});

	it("audits the upstream account's subject bounded: the IdP wrote it", async () => {
		const h = harness();
		await h.seed({ upstreamSubject: HOSTILE });

		const response = await request(h.app)
			.post(`/oauth/federation-grants/${GRANT_ID}/token`)
			.set("Authorization", basic())
			.send({ sub: "local-subject" });

		expect(response.status).toBe(200);
		await h.background.drain();
		const event = onlyEvent(h.events, "federation.grant.token.success");
		expect(
			shapeOf((event.details as { upstream?: { subject?: unknown } }).upstream?.subject),
		).toEqual(BOUNDED);
	});

	it("still audits an ordinary grant id and subject exactly", async () => {
		const h = harness();

		await request(h.app)
			.post("/oauth/federation-grants/g-unknown/token")
			.set("Authorization", basic())
			.send({ sub: "local-subject" });

		await h.background.drain();
		const event = onlyEvent(h.events, "federation.grant.token.denied");
		expect(grantIdOf(event)).toBe("g-unknown");
		expect(event.subject).toBe("local-subject");
	});
});
