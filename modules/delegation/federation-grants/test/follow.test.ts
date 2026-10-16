import { Unavailable } from "@mod/kernel";
import { seal } from "@mod/seal";
import { describe, expect, it } from "vitest";
import { grantStore } from "../src/store.ts";
import { back, harness } from "./harness.ts";

type Harness = Awaited<ReturnType<typeof harness>>;

const revocations = (h: Harness) =>
	h.events.filter((e) => e.kind === "federation.grant.revoked").map((e) => e.attributes?.outcome);
const listed = async (h: Harness) =>
	(await h.stores.subjects.members("alice")).map(({ member }) => member);

describe("following a subject's revocation", () => {
	it("leaves another subject's grant listed under it, and an intent started after the revocation", async () => {
		const h = await harness();
		const bobs = String((await h.lodge({ sub: "bob" })).json?.grant_id);
		await h.stores.subjects.add("alice", bobs, 60_000);
		await h.stores.subjects.add("alice", "gone", 60_000);
		h.advance(10_000);
		const late = String((await h.lodge()).json?.grant_id);
		// A host whose clock is behind records the revocation after the lodging.
		h.advance(-5000);
		await h.revoke("alice");
		expect(h.stores.peek(bobs)).toMatchObject({ status: "pending" });
		expect(h.stores.peek(late)).toMatchObject({ status: "pending" });
		expect(await listed(h)).toEqual([late]);
	});

	it("writes nothing over a revocation or a renewal another writer made meanwhile", async () => {
		const h = await harness();
		const { id } = await h.connected();
		h.meanwhile({ status: "revoked", reason: "client" });
		h.advance(1000);
		await h.revoke("alice");
		expect(h.stores.peek(id)).toMatchObject({ reason: "client" });
		expect(revocations(h)).toEqual([]);
		expect(await listed(h)).toEqual([]);
		for (const intent of [{ id: "another" }, { ended: "connected" }]) {
			const kept = await harness({ settings: { "keep-on-subject-revocation": true } });
			const { id: renewed } = await kept.connected();
			await kept.grantCall(renewed, "reauthorize", { redirect_uri: back, state: "r" });
			kept.meanwhile({}, intent);
			kept.advance(1000);
			await kept.revoke("alice", true);
			const left = (kept.stores.peek(renewed) as unknown as { intent: object }).intent;
			expect(left, JSON.stringify(intent)).toMatchObject(intent);
			expect(left).not.toHaveProperty("ended", "subject_revoked");
			expect(await listed(kept)).toEqual([renewed]);
		}
	});
});

describe("a grant's records", () => {
	it("opens no credentials sealed for another subject or of another shape", async () => {
		const h = await harness();
		const { id } = await h.connected();
		await h.app.get(grantStore).change(id, (r) => ({ value: { ...r, subject: "bob" } as never }));
		expect((await h.grantCall(id, "token", { sub: "bob" })).json?.error_description).toBe(
			"credentials_unreadable",
		);
		const { id: other } = await h.connected();
		const context = `federation-grants\n${other}\nalice\nworker\ncal`;
		const sealed = h.app.get(seal).seal(JSON.stringify({ accessToken: "x" }), context);
		await h.app.get(grantStore).change(other, (r) => ({ value: { ...r, sealed } as never }));
		expect((await h.grantCall(other, "token")).json?.error_description).toBe(
			"credentials_unreadable",
		);
	});

	it("reads a step of another shape as none", async () => {
		const h = await harness();
		const lodged = await h.lodge();
		const id = String(lodged.json?.grant_id);
		const intent = (h.stores.peek(id) as unknown as { intent: { id: string } }).intent.id;
		await h.stores.steps.create(
			"odd",
			{ format: 2, kind: "link", grant: id, intent } as never,
			60_000,
		);
		const opened = await h.browse("GET", "/session/federation-grants/connect", await h.login(), {
			request: "odd",
		});
		expect(opened.status).toBe(400);
	});

	it("lodges a grant whose listing failed, logging only the kind of failure", async () => {
		const h = await harness();
		h.stores.subjects.add = async () => {
			throw new Unavailable("listing");
		};
		expect((await h.lodge()).status).toBe(201);
		expect(h.logs()).toContainEqual({
			level: "warn",
			event: "federation-grants.listing_failed",
			fields: { kind: "Unavailable" },
		});
	});
});
