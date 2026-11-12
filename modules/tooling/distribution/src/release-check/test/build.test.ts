import { expect, it } from "vitest";
import { buildArguments } from "../image.ts";

it("builds the app's image on the install written beside it, its other stages as written", () => {
	expect(buildArguments({ image: "run:full", deps: "/s/deps-full", app: "/s/app" })).toEqual([
		"build",
		"-q",
		"-t",
		"run:full",
		"--build-context",
		"deps=/s/deps-full",
		"/s/app",
	]);
});

it("builds it fresh as the app's guide says: Node's image pulled, the stage the app runs in built again", () => {
	expect(
		buildArguments({ image: "run:full", deps: "/s/deps-full", app: "/s/app", fresh: true }),
	).toEqual([
		"build",
		"-q",
		"--pull",
		"--no-cache-filter=runtime",
		"-t",
		"run:full",
		"--build-context",
		"deps=/s/deps-full",
		"/s/app",
	]);
});
