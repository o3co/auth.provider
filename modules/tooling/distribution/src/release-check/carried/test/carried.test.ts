import { type Docker, DockerFailed } from "@mod/docker-client";
import { describe, expect, it } from "vitest";
import { withContainer } from "../../containers/container.ts";
import { carried } from "../carried.ts";

/** A daemon whose one-off container prints `found`, its arguments kept in `asked`. */
const daemon =
	(found: string, asked: string[][]): Docker =>
	async (args) => {
		asked.push([...args]);
		if (args[0] === "run") return found;
		if (args[0] === "inspect") throw new DockerFailed("absent", "inspect", "gone");
		return "";
	};
const look = (found: string, asked: string[][] = []) =>
	withContainer(
		{
			run: "release-check-1",
			purpose: "tools-simple-web",
			within: 5_000,
			docker: daemon(found, asked),
		},
		(c) => carried(c, "release-check-1:simple-web"),
	);

describe("the package managers an app's image carries", () => {
	it("are none where the image finds none", async () => {
		expect(await look("\n")).toEqual([]);
	});

	it("are each path the image still finds one at", async () => {
		const found =
			"/usr/local/bin/corepack\n/usr/local/lib/node_modules/corepack\n/opt/yarn-v1.22.22\n";
		expect(await look(found)).toEqual([
			"/usr/local/bin/corepack",
			"/usr/local/lib/node_modules/corepack",
			"/opt/yarn-v1.22.22",
		]);
	});

	it("are looked for in the image itself, past its entrypoint, with no network", async () => {
		const asked: string[][] = [];
		await look("", asked);
		const run = asked.find((args) => args[0] === "run") ?? [];
		const script = run.at(-1) ?? "";
		expect(run.slice(-5, -1)).toEqual(["--entrypoint", "sh", "release-check-1:simple-web", "-c"]);
		expect(run).toContain("--network=none");
		for (const tool of ["corepack", "pnpm", "yarn", "yarnpkg"]) expect(script).toContain(tool);
		expect(script).toContain("/usr/local/lib/node_modules/corepack");
		expect(script).toContain("/opt/yarn-v*");
	});
});
