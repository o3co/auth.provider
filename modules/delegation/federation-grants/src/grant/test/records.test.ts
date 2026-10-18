import { Unavailable } from "@mod/kernel";
import { seal } from "@mod/seal";
import { describe, expect, it } from "vitest";
import { harness, said } from "../../../test/harness.ts";
import { grantStore } from "../../store.ts";

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
	it("seals the credentials to the grant, so a copy under another grant does not open", async () => {
		const h = await harness();
		const a = await h.connected();
		const b = await h.connected();
		const sealedA = (h.stores.peek(a.id) as unknown as { sealed: string }).sealed;
		// Another writer copies the first grant's sealed credentials into the second.
		h.stores.raceNext((record) => ({ ...(record as object), sealed: sealedA }) as never);
		await h.app.get(grantStore).change(b.id, (r) => ({ value: r }));
		expect(said(await h.grantCall(b.id, "token"))).toBe(
			"410 reauthorization_required credentials_unreadable",
		);
		expect(JSON.stringify(h.stores.peek(a.id))).not.toContain("up-refresh-1");
	});
});
