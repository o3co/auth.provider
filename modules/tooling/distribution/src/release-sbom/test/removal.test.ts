import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { docker } from "@mod/docker-client";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import { endOf, notRemoved } from "../removal.ts";

// A `docker` of its own first on the path, answering as each test's script says.
const bin = mkdtempSync(join(tmpdir(), "release-sbom-docker-"));
afterAll(() => rmSync(bin, { recursive: true, force: true }));
afterEach(() => vi.unstubAllEnvs());
const client = (script: string) => {
	writeFileSync(join(bin, "docker"), `#!/bin/sh\n${script}\n`);
	chmodSync(join(bin, "docker"), 0o755);
	vi.stubEnv("PATH", `${bin}${delimiter}${process.env.PATH ?? ""}`);
};

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

it("tells a command past its time as such, beside what the client wrote before it stalled", async () => {
	client('echo "Pulling from anchore/syft" >&2; exec sleep 30');
	const ended = await endOf(docker(["run", "--rm", "syft"], 1_500));
	expect(ended.status).not.toBe(0);
	expect(ended.stderr).toBe(
		"Pulling from anchore/syft\ndocker run did not answer within 1.5 seconds",
	);
	client("exec sleep 30");
	expect((await endOf(docker(["image", "ls"], 300))).stderr).toBe(
		"docker image ls did not answer within 0.3 seconds",
	);
});

it("tells a command that failed in time by what the client wrote, and one that answered by its output", async () => {
	client('echo "conflict: in use" >&2; exit 1');
	expect(await endOf(docker(["image", "rm", "-f", "r:full"], 5_000))).toEqual({
		status: 1,
		stdout: "",
		stderr: "conflict: in use",
	});
	client('echo "r:base"');
	expect(await endOf(docker(["image", "ls"], 5_000))).toEqual({
		status: 0,
		stdout: "r:base",
		stderr: "",
	});
});
