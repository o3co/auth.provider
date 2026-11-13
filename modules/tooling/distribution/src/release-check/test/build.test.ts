import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generate } from "@mod/create-app";
import { expect, it } from "vitest";
import { buildArguments } from "../image.ts";

const root = join(import.meta.dirname, "..", "..", "..", "..", "..", "..");

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

it("rebuilds, fresh, a stage the Dockerfile of a generated app has", async () => {
	const target = join(mkdtempSync(join(tmpdir(), "build-test-")), "app");
	try {
		await generate({ target, template: "full", workspace: root });
		const stages = [
			...readFileSync(join(target, "Dockerfile"), "utf8").matchAll(/^FROM \S+ AS (\S+)$/gm),
		].map((m) => m[1]);
		const rebuilt = buildArguments({ image: "i", deps: "d", app: "a", fresh: true })
			.find((a) => a.startsWith("--no-cache-filter="))
			?.split("=")[1];
		expect(stages).toContain(rebuilt);
	} finally {
		rmSync(join(target, ".."), { recursive: true, force: true });
	}
});
