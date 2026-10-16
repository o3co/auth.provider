import { Unavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { answeringUnavailable } from "../src/contract.ts";

it("answers Unavailable as 503 temporarily_unavailable after noting it, and throws anything else on", async () => {
	const noted: unknown[] = [];
	const handle = answeringUnavailable(
		(request: string) => {
			if (request === "sync") throw new Unavailable("test");
			if (request === "bug") throw new Error("bug");
			return Promise.reject(new Unavailable("test"));
		},
		(request, { what }) => noted.push([request, what]),
	);
	for (const request of ["sync", "async"]) {
		expect(await handle(request)).toEqual({
			status: 503,
			headers: { "cache-control": "no-store", pragma: "no-cache" },
			body: { json: { error: "temporarily_unavailable" } },
		});
	}
	await expect(handle("bug")).rejects.toThrow("bug");
	expect(noted).toEqual([
		["sync", "test"],
		["async", "test"],
	]);
});
