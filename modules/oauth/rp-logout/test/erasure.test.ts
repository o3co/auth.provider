import { type Eraser, erasers } from "@mod/erasure-extensions";
import { BootRefused, contract, defineModule } from "@mod/kernel";
import { expect, it } from "vitest";
import { harness } from "./harness.ts";

it("refuses to start where the notice bodies offer part of erase and migrate", async () => {
	const refused = await harness({
		bodies: (bodies) => {
			delete (bodies as { migrate?: unknown }).migrate;
		},
	}).catch((e: unknown) => e);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals).toContainEqual({
		where: "rp-logout",
		reason: expect.stringMatching(/both, or neither/),
	});
});

it("contributes its eraser, `rp-logout`, erasable over bodies offering both ports, after no other", async () => {
	const found = contract<readonly Eraser[]>("found-erasers");
	const finder = defineModule({ name: "finder", replicaSafe: false, takes: [erasers] }, (m) => [
		m.provide(found).by((c) => c.collect(erasers)),
	]);
	const h = await harness({ extra: [finder] });
	try {
		const eraser = h.app.get(found).find((e) => e.name === "rp-logout");
		expect([eraser?.erasable, eraser?.after]).toEqual([true, undefined]);
	} finally {
		await h.stop();
	}
});
