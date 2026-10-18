import { Unavailable } from "@mod/kernel";
import { seal } from "@mod/seal";
import { describe, expect, it } from "vitest";
import { grantStore } from "../src/store.ts";
import { harness } from "./harness.ts";

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
