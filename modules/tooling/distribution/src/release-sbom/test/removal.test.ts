import { expect, it } from "vitest";
import { notRemoved } from "../removal.ts";

const listing = (images: string[]) => ({ status: 0, stdout: images.join("\n"), stderr: "" });

it("tells images not removed, by Docker's answer to their removal and its listing after", () => {
	expect(notRemoved(["r:full", "r:base"], { status: 0, stderr: "" }, listing([]))).toBeUndefined();
	expect(
		notRemoved(
			["r:full", "r:base"],
			{ status: 1, stderr: "conflict: in use" },
			listing(["r:base"]),
		),
	).toBe("image: r:base not removed (conflict: in use)");
	// Docker answered nothing wrong, yet one is still listed.
	expect(notRemoved(["r:full", "r:base"], { status: 0, stderr: "" }, listing(["r:full"]))).toBe(
		"image: r:full not removed",
	);
});

it("tells a listing that failed, never reading its empty output as nothing left", () => {
	expect(
		notRemoved(
			["r:full"],
			{ status: 1, stderr: "daemon down" },
			{ status: 1, stdout: "", stderr: "daemon down" },
		),
	).toBe("image: r:full may not be removed: Docker's images could not be listed (daemon down)");
});
