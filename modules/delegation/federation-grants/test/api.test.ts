import { testRequest } from "@mod/http/testing";
import { sessions } from "@mod/session";
import { describe, expect, it } from "vitest";
import { back, harness, said } from "./harness.ts";

describe("the client routes", () => {
	it("answers another client's, another subject's and an unknown grant with the same 404 on every route that takes a grant id", async () => {
		const h = await harness();
		const { id } = await h.connected();
		const renewal = { redirect_uri: back, state: "r" };
		for (const step of ["token", "status", "revoke", "reauthorize"]) {
			const more = step === "reauthorize" ? renewal : {};
			const answers = [
				await h.grantCall(id, step, more, "other"),
				await h.grantCall(id, step, { ...more, sub: "bob" }),
				await h.grantCall("unknown", step, more),
			];
			for (const answer of answers) expect(answer).toEqual(answers[0]);
			expect(answers[0]).toMatchObject({ status: 404, json: { error: "grant_not_found" } });
		}
		const lodged = await h.lodge({}, "other");
		expect(lodged.status).toBe(201);
		// Still standing: none of the refusals touched it.
		expect((await h.grantCall(id, "token")).status).toBe(200);
	});

	it("caps a lodging's lifetime, and answers the pending grant's status past its connection time", async () => {
		const h = await harness();
		const lodged = await h.lodge({ expires_in: 99_999_999 });
		expect(lodged.json?.expires_in).toBe(2_592_000);
		h.advance(601_000);
		const status = (await h.grantCall(String(lodged.json?.grant_id), "status")).json;
		expect(status).toMatchObject({ status: "pending", sub: "alice", client_id: "worker" });
	});

	it("counts lodgings per client whatever the subject, and answers 429 past the limit", async () => {
		const h = await harness({ settings: { lodges: 2 } });
		expect((await h.lodge({ sub: "a" })).status).toBe(201);
		expect((await h.lodge({ sub: "b" })).status).toBe(201);
		const third = await h.lodge({ sub: "c" });
		expect(said(third)).toBe("429 rate_limited provider 60");
		expect((await h.lodge({ sub: "c" }, "other")).status).toBe(201);
		expect(h.events.filter((e) => e.kind === "federation.grant.request.denied").length).toBe(1);
	});

	it("pushes out the oldest first-time intent of a pair past the cap, which then cannot connect", async () => {
		const h = await harness();
		const first = await h.started();
		for (const _ of [1, 2, 3]) {
			h.advance(1);
			await h.lodge();
		}
		const done = await h.callback(first.state, first.browser);
		expect(done.status).toBe(400);
		// A pair other than the crowded one is not touched.
		expect((await h.connected()).done.headers.location).toMatch("grant_id=");
	});

	it("keeps a client's revocation as the end: 204, again 204, then 410 and revoked", async () => {
		const h = await harness();
		const { id } = await h.connected();
		expect((await h.grantCall(id, "revoke")).status).toBe(204);
		expect((await h.grantCall(id, "revoke")).status).toBe(204);
		expect(said(await h.grantCall(id, "token"))).toBe("410 grant_revoked client");
		expect((await h.grantCall(id, "status")).json).toMatchObject({
			status: "revoked",
			reason: "client",
		});
		expect(h.events.filter((e) => e.kind === "federation.grant.revoked").length).toBe(1);
	});

	it("ends a grant at a subject's revocation unless kept, and keeps it only where the operator lets", async () => {
		const ended = await harness();
		const a = await ended.connected();
		ended.advance(1000);
		await ended.revoke("alice", true);
		expect(said(await ended.grantCall(a.id, "token"))).toBe("410 grant_revoked backstop");
		expect((await ended.grantCall(a.id, "status")).json?.status).toBe("revoked");
		expect(ended.events.map((e) => e.attributes?.outcome)).toContain("backstop");

		const kept = await harness({ settings: { "keep-on-subject-revocation": true } });
		const b = await kept.connected();
		kept.advance(1000);
		await kept.revoke("alice", true);
		expect((await kept.grantCall(b.id, "token")).status).toBe(200);
		kept.advance(1000);
		await kept.revoke("alice");
		expect((await kept.grantCall(b.id, "token")).status).toBe(410);
	});

	it("counts a grant made within its allowance after the subject's revocation as revoked", async () => {
		const h = await harness();
		await h.revoke("alice");
		h.advance(1000);
		const within = await h.connected();
		expect(h.location(within.done).searchParams.get("error")).toBe("access_denied");
		h.advance(1000);
		const after = await h.connected();
		expect(h.location(after.done).searchParams.get("error")).toBeNull();
		// A revocation another host placed a second behind this one's activation.
		h.advance(-1000);
		await h.revoke("alice");
		expect((await h.grantCall(after.id, "token")).status).toBe(410);

		const none = await harness({ settings: { "revocation-skew": "0s" } });
		await none.revoke("alice");
		none.advance(1000);
		const made = await none.connected();
		expect(none.location(made.done).searchParams.get("error")).toBeNull();
		none.advance(-1000);
		await none.revoke("alice");
		expect((await none.grantCall(made.id, "token")).status).toBe(200);
	});

	it("audits a subject's revocation of a grant only where this request wrote it", async () => {
		const h = await harness();
		const { id } = await h.connected();
		// Left off its subject's listing, so the revocation's closing work misses it.
		await h.stores.subjects.remove("alice", id);
		h.advance(1000);
		await h.revoke("alice");
		// Another writer revokes it first, between the read and the backstop's write.
		h.stores.raceNext(
			(record) => ({ ...(record as object), status: "revoked", reason: "client" }) as never,
		);
		expect(said(await h.grantCall(id, "token"))).toBe("410 grant_revoked client");
		expect(h.events.filter((e) => e.kind === "federation.grant.revoked")).toEqual([]);
	});

	it("ends a subject's grants when its revocation is recorded, erasing their credentials, and no other's", async () => {
		const h = await harness();
		const pending = String((await h.lodge()).json?.grant_id);
		const { id } = await h.connected();
		const bobs = String((await h.lodge({ sub: "bob" })).json?.grant_id);
		h.advance(1000);
		expect(await h.revoke("alice")).toEqual({ complete: true });
		for (const ended of [pending, id]) {
			expect(h.stores.peek(ended)).toMatchObject({ status: "revoked", reason: "backstop" });
			expect(h.stores.peek(ended)).not.toHaveProperty("sealed");
		}
		expect(h.stores.peek(bobs)).toMatchObject({ status: "pending" });
		const revoked = h.events.filter((e) => e.kind === "federation.grant.revoked");
		expect(revoked.map((e) => e.attributes?.outcome)).toEqual(["backstop", "backstop"]);
		expect((await h.grantCall(id, "token")).json?.error).toBe("grant_revoked");
		expect(h.events.filter((e) => e.kind === "federation.grant.revoked").length).toBe(2);
	});

	it("keeps established grants at a kept revocation, but ends pending ones and renewals in flight", async () => {
		const h = await harness({ settings: { "keep-on-subject-revocation": true } });
		const pending = await h.started();
		const { id } = await h.connected();
		const renewal = await h.grantCall(id, "reauthorize", { redirect_uri: back, state: "r" });
		h.advance(1000);
		expect(await h.revoke("alice", true)).toEqual({ complete: true });
		expect(h.stores.peek(pending.id)).toMatchObject({ status: "revoked" });
		expect(h.stores.peek(id)).toMatchObject({
			status: "active",
			intent: { ended: "subject_revoked" },
		});
		expect(h.stores.peek(id)).toHaveProperty("sealed");
		expect((await h.grantCall(id, "token")).status).toBe(200);
		expect((await h.open(renewal, await h.login())).opened.status).toBe(400);
	});

	it("ends the rest of a subject's grants when one cannot be ended, and says the revocation is incomplete", async () => {
		const h = await harness();
		const first = String((await h.lodge()).json?.grant_id);
		const second = String((await h.lodge()).json?.grant_id);
		h.stores.down.failNext("change");
		expect(await h.revoke("alice")).toEqual({ complete: false });
		const statuses = [first, second].map((id) => (h.stores.peek(id) as { status?: string }).status);
		expect(statuses.sort()).toEqual(["pending", "revoked"]);
	});

	it("leaves a grant standing when only its session closes", async () => {
		const h = await harness();
		const { id, browser } = await h.connected();
		const carrying = () => testRequest({ headers: new Map([["cookie", browser]]) });
		expect((await h.app.get(sessions).closeRequest(carrying())).kind).toBe("closed");
		expect(await h.app.get(sessions).enter(carrying())).toBeUndefined();
		expect((await h.grantCall(id, "token")).status).toBe(200);
	});

	it("erases the credentials of a grant past its life on any route, keeping its status", async () => {
		for (const step of ["status", "token", "reauthorize"]) {
			const h = await harness();
			const { id } = await h.connected();
			h.advance(2_592_000_000 - 1);
			await h.grantCall(id, "status");
			expect(h.stores.peek(id)).toHaveProperty("sealed");
			const read = (h.stores.peek(id) as unknown as { version: string }).version;
			h.advance(1);
			await h.grantCall(id, step, step === "reauthorize" ? { redirect_uri: back, state: "r" } : {});
			expect(h.stores.peek(id), step).not.toHaveProperty("sealed");
			// A new version, so a refresh that read the grant before writes nothing back.
			expect((h.stores.peek(id) as unknown as { version: string }).version, step).not.toBe(read);
			expect((await h.grantCall(id, "status")).json?.status).toBe("expired");
		}
	});

	it("erases the credentials of a grant past the longest life allowed now, after a restart that shortened it", async () => {
		const before = await harness();
		const { id } = await before.connected();
		const after = await harness({ stores: before.stores, settings: { "max-lifetime": "1m" } });
		after.advance(60_000);
		await after.grantCall(id, "status");
		expect(after.stores.peek(id)).not.toHaveProperty("sealed");
	});

	it("renews a grant through a new intent, keeping it usable until the renewal activates", async () => {
		const h = await harness();
		const { id } = await h.connected();
		const renewal = await h.grantCall(id, "reauthorize", { redirect_uri: back, state: "r" });
		expect(renewal).toMatchObject({ status: 201, json: { grant_id: id, status: "active" } });
		expect((await h.grantCall(id, "token")).status).toBe(200);
		expect(h.events.map((e) => e.attributes?.outcome)).toContain("reauthorization");
	});

	it("audits a refusal from the held credential by what refused it", async () => {
		const h = await harness();
		const { id } = await h.connected({ expiresInSeconds: 4 });
		h.advance(5000);
		h.script.refreshes.push({ kind: "invalid_grant" }, "refused");
		await h.grantCall(id, "token");
		await h.grantCall(id, "token");
		const denied = h.events.filter((e) => e.kind === "federation.grant.token.denied");
		expect(denied.map((e) => e.attributes?.reason)).toEqual([
			"upstream_invalid_grant",
			"reauthorization_required",
		]);
	});

	it("audits a refused revoke by the client, with why, before the grant is found", async () => {
		const h = await harness();
		const { id } = await h.connected();
		expect((await h.grantCall("nope", "revoke")).status).toBe(404);
		expect((await h.grantCall(id, "revoke", { sub: "" })).status).toBe(400);
		const denied = h.events.filter((e) => e.kind === "federation.grant.revoke.denied");
		expect(denied.map((e) => e.attributes?.reason)).toEqual(["grant_not_found", "sub_required"]);
		expect(denied.every((e) => e.subject === undefined)).toBe(true);
	});

	it("answers an allowed client when a grant's token was last handed out, never moving it back, nor failing for it", async () => {
		const h = await harness();
		const { id } = await h.connected();
		expect((await h.grantCall(id, "status")).json).not.toHaveProperty("last_used_at");
		h.advance(5000);
		const handedAt = new Date(h.now()).toISOString();
		expect((await h.grantCall(id, "token")).status).toBe(200);
		expect((await h.grantCall(id, "status")).json?.last_used_at).toBe(handedAt);
		// A later use another request wrote first stays.
		const later = h.now() + 60_000;
		h.stores.raceNext((record) => ({ ...(record as object), lastUsedAt: later }) as never);
		h.advance(1000);
		await h.grantCall(id, "token");
		expect((await h.grantCall(id, "status")).json?.last_used_at).toBe(
			new Date(later).toISOString(),
		);
		h.stores.down.failNext("change");
		expect((await h.grantCall(id, "token")).status).toBe(200);
		// Only a client still allowed the connection is told when it last used it.
		h.relist([], [back]);
		expect((await h.grantCall(id, "status")).json).not.toHaveProperty("last_used_at");
	});

	it("answers 503 when the store cannot tell, naming no cause, as for any cause", async () => {
		const h = await harness();
		const { id } = await h.connected();
		h.stores.down.failNext("read");
		const answer = await h.grantCall(id, "token");
		expect([answer.status, answer.json?.error]).toEqual([503, "temporarily_unavailable"]);
		expect(answer.json).not.toHaveProperty("error_description");
	});
});
