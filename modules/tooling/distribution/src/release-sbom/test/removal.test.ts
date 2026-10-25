import { expect, it } from "vitest";
import { notRemoved } from "../removal.ts";

it("tells images not removed, by Docker's answer to their removal and its listing after", () => {
	expect(notRemoved(["r:full", "r:base"], { status: 0, stderr: "" }, [])).toBeUndefined();
	expect(
		notRemoved(["r:full", "r:base"], { status: 1, stderr: "conflict: in use" }, ["r:base"]),
	).toBe("image: r:base not removed (conflict: in use)");
	// Docker answered nothing wrong, yet one is still listed.
	expect(notRemoved(["r:full", "r:base"], { status: 0, stderr: "" }, ["r:full"])).toBe(
		"image: r:full not removed",
	);
});
