import { expect, it } from "vitest";
import { pastBoundaries } from "../src/revocation.ts";

it("waits until the time is a second and more past the latest boundary recorded", async () => {
	const latest = Date.now();
	await pastBoundaries([latest - 5_000, latest]);
	expect(Math.floor(Date.now() / 1000)).toBeGreaterThan(Math.floor(latest / 1000));
});

it("waits for none already past, and refuses to wait past none recorded", async () => {
	const began = Date.now();
	await pastBoundaries([began - 5_000]);
	expect(Date.now() - began).toBeLessThan(1_000);
	await expect(pastBoundaries([])).rejects.toThrow("no boundary recorded");
});
