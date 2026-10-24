import { describe, expect, it } from "vitest";
import { withContainer } from "../containers/container.ts";
import { type Docker, DockerFailed } from "../containers/docker.ts";
import { settled } from "../image.ts";

/** A daemon whose container's state is `state` while it is there. */
const daemon =
	(state: string): Docker =>
	async (args) => {
		if (args[0] === "inspect" && args.includes("{{.State.Running}} {{.State.ExitCode}}"))
			return state;
		if (args[0] === "inspect") throw new DockerFailed("absent", "inspect", "gone");
		if (args[0] === "logs") return "the app's output";
		return "";
	};
const boot = (state: string, answered: () => Promise<boolean>, within: number) =>
	withContainer(
		{ run: "release-check-1", purpose: "boot-simple-web", within: 5_000, docker: daemon(state) },
		(c) => settled(c, answered, within),
	);

describe("a booted app waited on", () => {
	it("is ready once it answers ready", async () => {
		expect(await boot("true 0", async () => true, 1_000)).toEqual({ running: true, exitCode: 0 });
	});

	it("has ended once its container no longer runs", async () => {
		expect(await boot("false 78", async () => false, 1_000)).toEqual({
			running: false,
			exitCode: 78,
		});
	});

	it("fails where it neither answers ready nor ends in its time, nothing asked of it after", async () => {
		let asked = 0;
		const began = performance.now();
		const late = async () => {
			asked += 1;
			return false;
		};
		await expect(boot("true 0", late, 100)).rejects.toThrow(/neither ready nor ended within/);
		expect(performance.now() - began).toBeLessThan(1_000);
		const afterward = asked;
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(asked).toBe(afterward);
	});
});
