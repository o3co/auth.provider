import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { writeDeployment } from "../src/contract.ts";
import { fakePackages } from "./fake.ts";

const readme = {
	template: "pattern-readme.md",
	fill: { name: "simple-web", use: "A test.", card: "", chosen: "", receivers: "", deployment: "" },
};

const read = (target: string, path: string) => readFile(join(target, path), "utf8");

it("writes the deployment of the modules from the packages given", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeDeployment(target, ["@mod/http", "@mod/clients"], fakePackages(), readme);

	expect((await readdir(target, { recursive: true })).sort()).toEqual(
		[
			".dockerignore",
			".env.example",
			".gitignore",
			"AGENTS.md",
			"Dockerfile",
			"README.md",
			"config",
			"config/application.conf",
			"config/local.conf.example",
			"package.json",
			"src",
			"src/main.ts",
		].sort(),
	);
	const manifest = JSON.parse(await read(target, "package.json"));
	// The kernel and its configuration files come first, whether or not listed, and no reseal without seal.
	expect(Object.keys(manifest.dependencies)).toEqual([
		"@mod/kernel",
		"@mod/config-files",
		"@mod/http",
		"@mod/clients",
		"zod",
	]);
	expect(manifest.scripts).toEqual({ start: "node --env-file-if-exists=.env src/main.ts" });
	const main = await read(target, "src/main.ts");
	expect(main).toContain('from "@o3co/x-kernel"');
	// It checks, as it boots, the variables 0.17 read that its configuration never reads.
	expect(main).toContain("legacyVariablesCheck");
	expect(main).toContain("warn config-files: ");
	expect(main).toContain('import m0 from "@o3co/x-http/module";');
	expect(main).toContain('import m1 from "@o3co/x-clients/module";');

	expect(await read(target, "config/application.conf")).toContain(`port = \${?HTTP_PORT}`);
	const env = await read(target, ".env.example");
	expect(env).toContain("# HTTP_HOST=127.0.0.1");
	expect(env).toContain("# KERNEL_DEPLOYMENT=single");
	expect(await read(target, "config/local.conf.example")).toContain("# clients.redirect-uris = [");

	const agents = await read(target, "AGENTS.md");
	expect(agents).toContain(
		"| `@mod/http` | `node_modules/@mod/http/README.md` | `node_modules/@mod/http/reference.conf` |",
	);
	// Without a repository, no document of the release is pointed at.
	expect(agents).not.toContain("of the release");

	const guide = await read(target, "README.md");
	expect(guide).toContain("simple-web");
	expect(guide).toContain("| `http.port` | `HTTP_PORT` | `8080` |");
	expect(guide).not.toContain("{{");
	expect(guide).not.toContain("What the composed modules ask of the deployment");
	expect(guide).not.toContain("A first login");
});

it("points at the release's documents and the cards that ask of the deployment", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	const release = { version: "1.2.3", repository: "https://example.invalid/auth" };
	await writeDeployment(target, ["@mod/http"], fakePackages(release, ["@mod/http"]), readme);

	const agents = await read(target, "AGENTS.md");
	expect(agents).toContain("https://example.invalid/auth/blob/v1.2.3/docs/configuration.md");
	const guide = await read(target, "README.md");
	expect(guide).toContain("## What the composed modules ask of the deployment");
	expect(guide).toContain("- `@mod/http`: `node_modules/@mod/http/README.md#deployment`");
	expect(guide).toContain("https://example.invalid/auth/blob/v1.2.3/docs/recipe-first-login.md");
});

it("checks 0.17's variables in every entry through config-files' check alone, choosing nothing itself", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeDeployment(target, ["@mod/seal", "@mod/mfa-witnessing"], fakePackages(), readme);
	for (const entry of ["src/main.ts", "src/reseal.ts", "src/witness-backfill.ts"]) {
		const source = await read(target, entry);
		expect(source, entry).toContain("await legacyVariablesCheck(source)");
		expect(source, entry).not.toContain("unreadLegacyVariables");
		expect(source, entry).not.toContain("APP_LEGACY_VARIABLES");
	}
});

it("tells a refused boot in its entries by the kernel's mark, never by its class", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeDeployment(target, ["@mod/seal", "@mod/mfa-witnessing"], fakePackages(), readme);
	for (const entry of ["src/main.ts", "src/reseal.ts", "src/witness-backfill.ts"]) {
		const source = await read(target, entry);
		expect(source, entry).toContain("BootRefused.is(error)");
		expect(source, entry).not.toContain("instanceof");
	}
});

it("adds the reseal entry when seal is composed", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeDeployment(target, ["@mod/seal"], fakePackages(), readme);

	const manifest = JSON.parse(await read(target, "package.json"));
	expect(manifest.scripts.reseal).toBe("node --env-file-if-exists=.env src/reseal.ts");
	expect(await read(target, "src/reseal.ts")).toContain('from "@o3co/x-seal"');
});

it("adds the witness-backfill entry when mfa-witnessing is composed", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeDeployment(target, ["@mod/mfa-witnessing"], fakePackages(), readme);

	const manifest = JSON.parse(await read(target, "package.json"));
	expect(manifest.scripts["witness-backfill"]).toBe(
		"node --env-file-if-exists=.env src/witness-backfill.ts",
	);
	expect(manifest.scripts.reseal).toBeUndefined();
	expect(await read(target, "src/witness-backfill.ts")).toContain(
		'import("@o3co/x-mfa-witnessing")',
	);
});

it("adds the passkey-backfill entry when passkey-witnessing is composed, settling through passkeyBackfill", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeDeployment(target, ["@mod/passkey-witnessing"], fakePackages(), readme);

	const manifest = JSON.parse(await read(target, "package.json"));
	expect(manifest.scripts["passkey-backfill"]).toBe(
		"node --env-file-if-exists=.env src/passkey-backfill.ts",
	);
	expect(manifest.scripts["witness-backfill"]).toBeUndefined();
	const entry = await read(target, "src/passkey-backfill.ts");
	expect(entry).toContain("{ passkeyBackfill }");
	expect(entry).toContain('import("@o3co/x-passkey-witnessing")');
	expect(entry).toContain('["marked", "held", "none", "pending", "inconsistent"]');
});

it("adds the unclaimed-factors entry where mfa-reset is composed, asking resetCandidates", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeDeployment(target, ["@mod/mfa-reset"], fakePackages(), readme);

	const manifest = JSON.parse(await read(target, "package.json"));
	expect(manifest.scripts["unclaimed-factors"]).toBe(
		"node --env-file-if-exists=.env src/unclaimed-factors.ts",
	);
	const entry = await read(target, "src/unclaimed-factors.ts");
	expect(entry).toContain("{ resetCandidates }");
	expect(entry).toContain('import("@o3co/x-mfa-reset")');
});

it("refuses a target that holds anything, and writes nothing", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeFile(join(target, "kept"), "");
	await expect(writeDeployment(target, ["@mod/http"], fakePackages(), readme)).rejects.toThrow(
		`${target} is not empty`,
	);
	expect(await readdir(target)).toEqual(["kept"]);
});

it("fills a listed app's guide with the modules listed and the caller's lines", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeDeployment(target, ["@mod/http"], fakePackages(), {
		template: "listed-readme.md",
		fill: {
			listed: "`@mod/http`",
			chosen: "",
			decided: "- `kernel.deployment`: `single` for one instance, `multi` for several.",
		},
	});

	const guide = await read(target, "README.md");
	expect(guide).toContain("from the modules listed: `@mod/http`.");
	expect(guide).toContain("- `kernel.deployment`: `single` for one instance, `multi` for several.");
	expect(guide).toContain("| `http.port` | `HTTP_PORT` | `8080` |");
	expect(guide).not.toContain("{{");
});

const listedReadme = (listed: string) => ({
	template: "listed-readme.md",
	fill: { listed, chosen: "", decided: "" },
});

it("promises no http, port or health check to an app that composes no http", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeDeployment(target, ["@mod/redis"], fakePackages(), listedReadme("`@mod/redis`"));

	const docker = await read(target, "Dockerfile");
	for (const http of ["HEALTHCHECK", "EXPOSE", "HTTP_HOST", "HTTP_PORT", "_healthcheck"]) {
		expect(docker).not.toContain(http);
	}
	const guide = await read(target, "README.md");
	for (const http of ["_healthcheck", "/readyz", "-p 8080", "HTTP_PORT", "plain http", "listens"]) {
		expect(guide).not.toContain(http);
	}
	expect(guide).toContain("docker run --env-file .env -e APP_CONFIG=");
	expect(guide).toContain(
		"set `APP_LEGACY_VARIABLES=refuse` to refuse boot on one instead, or `ignore`",
	);
	expect(guide).not.toContain("{{");
});

it("listens and exposes the port where http is composed, and checks liveness where http-ops is", async () => {
	const served = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeDeployment(served, ["@mod/http"], fakePackages(), listedReadme("`@mod/http`"));
	const docker = await read(served, "Dockerfile");
	expect(docker).toContain("ENV HTTP_HOST=0.0.0.0");
	expect(docker).toContain("EXPOSE ${HTTP_PORT}");
	expect(docker).not.toContain("HEALTHCHECK");
	const guide = await read(served, "README.md");
	expect(guide).toContain("-p 8080:8080");
	expect(guide).toContain("To try it on this machine over plain http");
	expect(guide).not.toContain("_healthcheck");

	const live = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeDeployment(
		live,
		["@mod/http", "@mod/http-ops"],
		fakePackages(),
		listedReadme("`@mod/http`"),
	);
	expect(await read(live, "Dockerfile")).toContain("/_healthcheck");
	expect(await read(live, "README.md")).toContain("Its health check asks `/_healthcheck`");
});

it("builds on Node 24's latest, so a build takes its security fixes", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeDeployment(target, ["@mod/http"], fakePackages(), listedReadme("`@mod/http`"));
	const docker = await read(target, "Dockerfile");
	expect(docker).toMatch(/^FROM node:24-alpine AS base$/m);
	expect(docker).not.toContain("@sha256:");
});

it("records the packages outside the release and checks the lockfile against them, where the app composes one", async () => {
	const grant = {
		name: "@x/grant",
		version: "1.2.0",
		integrity: "sha512-AAAA",
		dependencies: {},
		optionalDependencies: {},
		peerDependencies: { zod: "^4.6.0" },
		peerDependenciesMeta: {},
	};
	const outside = { modules: [grant], registries: { default: "https://registry.npmjs.org" } };
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	const release = { version: "1.2.3", integrity: { zod: "sha512-ZOD" } };
	await writeDeployment(target, ["@mod/http"], fakePackages(release, [], outside), readme);
	const files = await readdir(target, { recursive: true });
	expect(files).toEqual(
		expect.arrayContaining([
			"outside-modules.json",
			"pnpm-workspace.yaml",
			"scripts/check-outside.mjs",
		]),
	);
	// What the release recorded of the packages held to one copy reaches the record.
	expect(JSON.parse(await read(target, "outside-modules.json")).held).toEqual({
		zod: "sha512-ZOD",
	});
	const manifest = JSON.parse(await read(target, "package.json"));
	expect(manifest.scripts["check:outside"]).toBe("node scripts/check-outside.mjs");
	// The check holds what it uses: the app depends on nothing for it.
	expect(manifest.dependencies).not.toHaveProperty("semver");
	expect(manifest.dependencies).not.toHaveProperty("yaml");
	const docker = await read(target, "Dockerfile");
	expect(docker).toContain("COPY outside-modules.json ./outside-modules.json");
	expect(docker).toContain("RUN pnpm install --frozen-lockfile --prod && pnpm check:outside");
	expect(await read(target, "README.md")).toContain("## Packages outside this release");
	expect(await read(target, "AGENTS.md")).toContain("`outside-modules.json`");
});
