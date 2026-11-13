import { execFileSync, spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterAll, expect, it } from "vitest";

// A `docker` of its own first on the path, logging each command and answering as the test's script says.
const scratch = mkdtempSync(join(tmpdir(), "image-scan-test-"));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
const scan = join(import.meta.dirname, "..", "scan.ts");

/** Packs `files` into `into` as `<name>-9.9.9.tgz`; `cli.mjs`, where given, made executable. */
const packed = (into: string, name: string, files: Readonly<Record<string, string>>) => {
	const at = join(scratch, `${name}-src`);
	mkdirSync(join(at, "package"), { recursive: true });
	for (const [path, text] of Object.entries(files)) writeFileSync(join(at, "package", path), text);
	if (files["cli.mjs"]) chmodSync(join(at, "package", "cli.mjs"), 0o755);
	execFileSync("tar", ["-czf", join(into, `${name}-9.9.9.tgz`), "package"], { cwd: at });
};

/**
 * An entrance of its own, packed with its bundle, whose `combinations` opts nothing in: its command
 * writes an app with a Dockerfile and a manifest.
 */
const entranceTarball = (into: string) => {
	packed(into, "o3co-create-auth-provider", {
		"package.json": JSON.stringify({
			name: "@o3co/create-auth-provider",
			version: "9.9.9",
			bin: { "create-auth-provider": "cli.mjs" },
			dependencies: { "@o3co/auth-provider-scaffold": "9.9.9" },
		}),
		"cli.mjs": `#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const app = process.argv[2];
mkdirSync(app, { recursive: true });
writeFileSync(join(app, "package.json"), '{"name":"app","private":true}');
writeFileSync(join(app, "Dockerfile"), "FROM scratch AS runtime\\n");
`,
	});
	packed(into, "o3co-auth-provider-scaffold", {
		"package.json": JSON.stringify({
			name: "@o3co/auth-provider-scaffold",
			version: "9.9.9",
			type: "module",
			exports: { "./combinations": "./combinations.js" },
		}),
		"combinations.js": "export const optIns = () => [];\n",
	});
};

const run = (name: string, answers: string, withEntrance: boolean) => {
	const dir = join(scratch, name);
	const bin = join(dir, "bin");
	const tarballs = join(dir, "tarballs");
	const out = join(dir, "out");
	mkdirSync(bin, { recursive: true });
	mkdirSync(tarballs);
	if (withEntrance) entranceTarball(tarballs);
	const log = join(dir, "log");
	writeFileSync(join(bin, "docker"), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${log}'\n${answers}\n`);
	chmodSync(join(bin, "docker"), 0o755);
	const ran = spawnSync(process.execPath, [scan, tarballs, out], {
		encoding: "utf8",
		env: { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH ?? ""}` },
	});
	return {
		status: ran.status,
		commands: existsSync(log) ? readFileSync(log, "utf8").trim().split("\n") : [],
		report: readFileSync(join(out, "README.md"), "utf8"),
	};
};

/** Docker answering every command but those `answers` names. */
const docker = (answers: string) => `case "$1" in
info) echo 29.0.0 ;;
inspect) echo 'Error: No such object' >&2; exit 1 ;;
${answers}
esac`;

it("fails a directory with no entrance as not scanned, building nothing", () => {
	const { status, commands, report } = run("empty", docker(""), false);
	expect(status).toBe(1);
	expect(report).toContain("**Failed.**");
	expect(report).toContain("Not scanned: no @o3co/create-auth-provider tarball in ");
	expect(commands.filter((c) => c.startsWith("build"))).toEqual([]);
});

it("fails where the image cannot be saved, never passing, and removes the images it built", () => {
	const { status, commands, report } = run(
		"unsaved",
		docker("save) echo 'Error: no space left on device' >&2; exit 1 ;;"),
		true,
	);
	expect(status).toBe(1);
	expect(report).toContain("**Failed.**");
	expect(report).toContain("Not scanned:");
	const built = commands.filter((c) => c.startsWith("build "));
	expect(built.at(-1)).toMatch(/^build -q --pull --no-cache-filter=runtime -t image-scan-/);
	expect(commands.some((c) => c.startsWith("save "))).toBe(true);
	// Trivy never ran on an image not saved.
	expect(commands.some((c) => c.includes(" image --input "))).toBe(false);
	expect(commands.at(-1)).toMatch(/^image rm -f image-scan-.*:base image-scan-.*:full$/);
}, 120_000);
