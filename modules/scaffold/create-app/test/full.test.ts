import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { full, optIns } from "@mod/combinations";
import { trialLayer } from "@mod/trial";
import { expect, it, vi } from "vitest";
import { generate } from "../src/contract.ts";
import {
	boot,
	configFiles,
	kernel,
	manifest,
	readsScalarsFromEnv,
	refusesEmptyOnlyForSections,
	refusesGeneratedOnlyForNamedKeys,
	writesListsLocally,
} from "./checks.ts";
import {
	configured,
	packageDirs as dirs,
	generated,
	importedModules as imports,
	installed,
	linked,
	read,
	root,
} from "./full-app.ts";

// These tests read the whole workspace and boot the app, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 120_000 });

const manifests = [...dirs.keys()].filter((n) => dirs.get(n) !== root).map(manifest);

it("assembles what combinations composes in full, each axis with one adapter, and depends on it and the kernel", async () => {
	const target = await generated();
	const modules = full();
	expect(await imports(target)).toEqual(modules);
	const pkg = JSON.parse(await read(target, "package.json"));
	expect(Object.keys(pkg.dependencies)).toEqual([kernel, configFiles, ...modules, "zod"]);
	// An app writing sections of its own holds the one zod the kernel asks of it as a peer: the
	// version the workspace tests with, within the kernel's range.
	const kernelManifest = manifest(kernel) as {
		readonly peerDependencies?: Record<string, string>;
		readonly devDependencies?: Record<string, string>;
	};
	expect(pkg.dependencies.zod).toBe(kernelManifest.devDependencies?.zod);
	const [major, minor] = String(pkg.dependencies.zod).split(".");
	expect(kernelManifest.peerDependencies?.zod).toBe(`^${major}.${minor}.0`);
	expect(pkg.scripts).toEqual({
		start: "node --env-file-if-exists=.env src/main.ts",
		reseal: "node --env-file-if-exists=.env src/reseal.ts",
		"unclaimed-factors": "node --env-file-if-exists=.env src/unclaimed-factors.ts",
	});
	const composed = modules.map(manifest);
	const owners = composed.flatMap((m) => m.replaces ?? m.adapts ?? []);
	expect(owners.length).toBeGreaterThan(0);
	expect(new Set(owners).size).toBe(owners.length);
	for (const m of composed) {
		expect(m.optIn, m.name).not.toBe(true);
		if (m.replaces) expect(modules, m.name).not.toContain(m.replaces);
	}
	// The guide lists what the template leaves out, to add.
	const readme = await read(target, "README.md");
	for (const name of optIns()) expect(readme).toContain(`- \`${name}\``);
});

it("names by hand only the keys no module's example holds", async () => {
	const readme = await read(await generated(), "README.md");
	const section = readme.split("## Keys no example holds")[1]?.split("\n## ")[0] ?? "";
	expect([...section.matchAll(/^- `([a-z0-9.-]+)`/gm)].map((m) => m[1])).toEqual([
		"authorize.step-up-page",
		"federation.held-page",
		"http.trusted-proxies",
		"http.client-certificate",
		"users.registered",
		"users-http.credential",
		"mail-smtp.user",
		"mail-smtp.password",
		"clients.registered",
	]);
	// Every other key the guide names comes from the fragments.
	for (const heading of ["Values the operator decides", "Pages the operator serves", "Secrets"]) {
		expect(readme).not.toContain(`## ${heading}`);
	}
});

it("writes a witness-backfill script where the enrollment witness is kept, and none where it is not", async () => {
	const kept = await generated(["@mod/mfa-witness-http"]);
	const pkg = JSON.parse(await read(kept, "package.json"));
	expect(pkg.scripts["witness-backfill"]).toBe(
		"node --env-file-if-exists=.env src/witness-backfill.ts",
	);
	expect(await read(kept, "src/witness-backfill.ts")).toMatch(/witnessBackfill/);
	const plain = JSON.parse(await read(await generated(), "package.json"));
	expect(plain.scripts["witness-backfill"]).toBeUndefined();
});

it("writes a passkey-backfill script where passkey logins keep the passkey witness", async () => {
	const kept = await generated(["@mod/webauthn-login", "@mod/passkey-witness-http"]);
	const pkg = JSON.parse(await read(kept, "package.json"));
	expect(pkg.scripts["passkey-backfill"]).toBe(
		"node --env-file-if-exists=.env src/passkey-backfill.ts",
	);
	expect(await read(kept, "src/passkey-backfill.ts")).toMatch(/passkeyBackfill/);
});

it("assembles the features added, with their wirings, bridges and default adapters", async () => {
	const add = ["@mod/device-grant", "@mod/mfa-email"];
	const target = await generated(add);
	const modules = await imports(target);
	expect(modules).toEqual(full(add));
	for (const feature of add) {
		expect(modules).toContain(feature);
		const wirings = manifests.filter((m) => m.wires === feature).map((m) => m.name);
		const adapters = manifests.filter((m) => (m.replaces ?? m.adapts) === feature);
		const chosen = adapters.length === 1 ? adapters : adapters.filter((m) => m.default);
		expect(modules).toEqual(expect.arrayContaining([...wirings, ...chosen.map((m) => m.name)]));
	}
	expect(modules).toContain("@mod/device-grant-store");
	for (const bridge of manifests.filter((m) => m.joins?.every((j) => modules.includes(j)))) {
		expect(modules, bridge.name).toContain(bridge.name);
	}
	// The added feature's fragment is collected with the rest.
	expect(await read(target, "config/application.conf")).toMatch(
		/^\tverification-uri = \$\{\?DEVICE_GRANT_VERIFICATION_URI\}$/m,
	);
});

it("adds federation grants with the browser half that runs them, which the full app holds neither of, and boots", async () => {
	const grants = ["@mod/federation-grants", "@mod/federation-grants-connect"];
	for (const name of grants) expect(full(), name).not.toContain(name);
	const target = await linked(await generated(["@mod/federation-grants"]));
	expect(await imports(target)).toEqual(expect.arrayContaining(grants));
	const pkg = JSON.parse(await read(target, "package.json"));
	for (const name of grants) expect(pkg.dependencies, name).toHaveProperty(name);
	// The browser half's page is its own section's, read from env as the rest.
	expect(await read(target, "config/application.conf")).toMatch(
		/^\tpage = \$\{\?FEDERATION_GRANTS_CONNECT_PAGE\}$/m,
	);
	// federation-grants takes exactly one browser half: booting shows the bridge is composed.
	await configured(target, { deployment: "single", redisUrl: "redis://127.0.0.1:1" });
	const run = boot(target, "config/local.conf,config/application.conf");
	expect(run.status, run.stderr).toBe(78);
	expect(run.refused, run.stderr).toEqual(["redis.url"]);
});

it("reads each scalar of the composed modules' fragments from env, one variable each, holding no value", async () => {
	await readsScalarsFromEnv(await generated(), full());
});

it("puts the fragments' lists, and a value spanning sections, in the local layer's example as comments only", async () => {
	await writesListsLocally(await generated(), full());
});

it("runs the image on its own interface and port, whatever the .env of a run on the host names", async () => {
	const target = await generated();
	expect(await read(target, ".env.example")).toContain("# HTTP_HOST=127.0.0.1");
	// -e after --env-file wins, so the container listens where the port mapping reaches.
	expect(await read(target, "README.md")).toMatch(
		/`docker run --env-file \.env -e HTTP_HOST=0\.0\.0\.0 -e HTTP_PORT=8080 [^`]* -p 8080:8080 auth-provider`/,
	);
});

it("writes the image, and what git and the image leave out", async () => {
	const target = await generated();
	const docker = await read(target, "Dockerfile");
	// A Node 24 or later image; which tag it follows is app-output's, held by its own test.
	expect(docker).toMatch(/^FROM node:2[4-9]\S* AS base$/m);
	// Dependencies are installed in their own stage; the image takes only what they left.
	expect(docker.match(/^FROM .*$/gm)).toEqual([
		"FROM " + docker.match(/^FROM (\S+) AS base$/m)?.[1] + " AS base",
		"FROM base AS deps",
		"FROM base AS runtime",
	]);
	expect(docker).toMatch(/^COPY --from=deps \/app\/node_modules \.\/node_modules$/m);
	expect(docker).toMatch(/^USER node$/m);
	// An init as process 1 passes signals on and reaps what node leaves behind; pnpm comes through a pinned corepack.
	expect(docker).toMatch(
		/^RUN apk add --no-cache tini && npm install --global corepack@\d+\.\d+\.\d+ && corepack enable$/m,
	);
	expect(docker).toMatch(/^ENTRYPOINT \["\/sbin\/tini", "--"\]$/m);
	expect(docker).toContain("pnpm install --frozen-lockfile --prod");
	// The workspace file, where the operator writes one, installs as pnpm reads it; none is needed.
	expect(docker).toMatch(/^COPY package\.json pnpm-lock\.yaml pnpm-workspace\.yam\[l\] \.\/$/m);
	expect(docker).toMatch(
		/^HEALTHCHECK --interval=30s --timeout=5s --start-period=\d+s --retries=3 .*\/_healthcheck/m,
	);
	const manifest = JSON.parse(await read(target, "package.json"));
	expect(manifest.packageManager).toMatch(/^pnpm@\d+\.\d+\.\d+$/);
	expect(docker).not.toContain("/readyz");
	expect(docker).toMatch(/^ENV HTTP_HOST=0\.0\.0\.0$/m);
	// The port is http's, read from HTTP_PORT by the generated configuration, and the health check follows it.
	expect(docker).toMatch(/^ENV HTTP_PORT=8080$/m);
	expect(docker).toMatch(/^EXPOSE \$\{HTTP_PORT\}$/m);
	expect(docker).toMatch(/^HEALTHCHECK .*process\.env\.HTTP_PORT.*\/_healthcheck/m);
	expect(await read(target, "config/application.conf")).toMatch(/^\tport = \$\{\?HTTP_PORT\}$/m);
	expect((await read(target, ".dockerignore")).split("\n")).toEqual(
		expect.arrayContaining([
			".git",
			".env",
			".env.*",
			"config/local*.conf",
			"*.pem",
			"*.key",
			"node_modules/",
		]),
	);
	// Env files of any name and key files stay out of git; the examples go in.
	expect((await read(target, ".gitignore")).split("\n")).toEqual([
		"node_modules/",
		"config/local*.conf",
		".env",
		".env.*",
		"!.env.example",
		"*.pem",
		"*.key",
		"",
	]);
});

it("refuses an added name the workspace lacks or that is not a feature, before writing anything", async () => {
	const parent = await mkdtemp(join(tmpdir(), "create-app-"));
	const target = join(parent, "app");
	for (const [add, reason] of [
		["@mod/nowhere", "@mod/nowhere: not in the workspace"],
		[kernel, `${kernel}: not a feature or an adapter with a module`],
		["../up", "../up is not a package name"],
	] as const) {
		await expect(generate({ target, template: "full", add: [add] }), add).rejects.toThrow(
			new Error(reason),
		);
	}
	const held = await mkdtemp(join(tmpdir(), "create-app-"));
	await writeFile(join(held, "mine"), "");
	await expect(generate({ target: held, template: "full" })).rejects.toThrow("not empty");
	expect(existsSync(target)).toBe(false);
});

it("refuses an empty configuration only for the composed modules' sections and the kernel's", async () => {
	await refusesEmptyOnlyForSections(await installed(), full());
});

it("refuses the generated configuration alone only for keys the guide names", async () => {
	await refusesGeneratedOnlyForNamedKeys(await installed());
});

it("boots on the generated configuration with the environment and local layer filled, refused only for an unreachable Redis", async () => {
	const target = await installed();
	// Nothing listens on port 1.
	await configured(target, { deployment: "single", redisUrl: "redis://127.0.0.1:1" });
	const run = boot(target, "config/local.conf,config/application.conf");
	expect(run.status, run.stderr).toBe(78);
	expect(run.refused, run.stderr).toEqual(["redis.url"]);
});

it("makes the full template from the command with features added, and the listed packages' app", async () => {
	const cli = (...args: string[]) =>
		spawnSync(process.execPath, [join(import.meta.dirname, "..", "src", "main.ts"), ...args], {
			encoding: "utf8",
		});
	const parent = await mkdtemp(join(tmpdir(), "create-app-cli-"));
	const made = cli(join(parent, "full"), "--workspace", root, "--add", "@mod/device-grant");
	expect(made.status, made.stderr).toBe(0);
	expect(await imports(join(parent, "full"))).toEqual(full(["@mod/device-grant"]));
	const listed = cli(join(parent, "listed"), "--workspace", root, "@mod/http");
	expect(listed.status, listed.stderr).toBe(0);
	expect(await imports(join(parent, "listed"))).toEqual(
		expect.arrayContaining(["@mod/http", "@mod/log-stdout"]),
	);
	// Written as a deployment, as the full template is.
	expect(existsSync(join(parent, "listed", "Dockerfile"))).toBe(true);
	for (const args of [
		[join(parent, "both"), "--add", "@mod/device-grant", "@mod/http"],
		[join(parent, "sink"), "--sink", "@mod/log-stdout"],
		[],
	]) {
		expect(cli(...args).status, args.join(" ")).toBe(64);
	}
});

it("gives a generated app a trial layer by its own modules, with hosts under .invalid, leaving the sections the caller names", async () => {
	const target = await generated();
	const all = JSON.parse(await trialLayer(target, { redisUrl: "redis://127.0.0.1:1" }));
	const hosts = [...JSON.stringify(all).matchAll(/[a-z0-9-]+(?:\.[a-z0-9-]+)+(?=[/:"\s,\]]|$)/gm)]
		.map((m) => m[0])
		.filter((host) => /[a-z]/.test(host) && !/^\d/.test(host));
	expect(hosts.length).toBeGreaterThan(0);
	for (const host of hosts) expect(host, host).toMatch(/\.invalid$/);
	const left = JSON.parse(
		await trialLayer(target, { redisUrl: "redis://127.0.0.1:1", leave: ["keys", "http"] }),
	);
	expect(Object.keys(left).sort()).toEqual(
		Object.keys(all)
			.filter((section) => section !== "keys" && section !== "http")
			.sort(),
	);
});

it("tells the operator to set the page a federation login a second factor holds goes on at", async () => {
	expect(await read(await generated(), "README.md")).toContain(
		"- `federation.held-page`: the page a federation login a second factor holds goes on at, on the public origin; without it, the browser stops at the factor's answer.",
	);
});

it("stops within the kernel's own deadline, and tells the operator to give the orchestrator longer", async () => {
	const target = await generated();
	const main = await read(target, "src/main.ts");
	expect(main).toContain("await app.stop();");
	expect(main).not.toMatch(/stop\(\d/);
	expect(await read(target, "README.md")).toMatch(
		/grace period longer than `kernel\.stop-deadline`/,
	);
});

it("indexes for agents each composed module's card and section defaults as installed, and the release's whole lists", async () => {
	const target = await installed();
	const index = await read(target, "AGENTS.md");
	const pkg = JSON.parse(await read(target, "package.json"));
	// zod, beside the modules, is no module: the index lists modules alone.
	const composed = Object.keys(pkg.dependencies).filter((name) => name !== "zod");
	const rows = [...index.matchAll(/^\| `(@[^`]+)` \| `([^`]+)` \| (?:`([^`]+)`)? \|$/gm)];
	expect(rows.map((r) => r[1])).toEqual(composed);
	for (const [, name, card, references] of rows) {
		expect(existsSync(join(target, String(card))), String(name)).toBe(true);
		if (references) expect(existsSync(join(target, references)), String(name)).toBe(true);
	}
	expect(rows.some((r) => r[3] !== undefined)).toBe(true);
	expect(index).toMatch(/is the truth about it/);
	expect(index).toMatch(
		/https:\/\/github\.com\/o3co\/auth\.provider\/blob\/v[^/]+\/docs\/configuration\.md/,
	);
	const readme = await read(target, "README.md");
	for (const name of composed)
		expect(readme).toContain(`- \`${name}\`: \`node_modules/${name}/README.md\``);
});

it("tells in the full template's README the command's name, how to try it over plain http on this machine, and where to see what --add takes", async () => {
	const readme = await read(await generated(), "README.md");
	expect(readme).toContain("Generated by `create-auth-provider` from the full template");
	expect(readme).not.toContain("`create-app`");
	expect(readme).toMatch(
		/`http\.public-origin` to `http:\/\/localhost:8080` and `http\.insecure-origin` to `true`/,
	);
	expect(readme).toContain("`create-auth-provider --list`");
	expect(readme).toMatch(
		/A first login, step by step: https:\/\/github\.com\/o3co\/auth\.provider\/blob\/v[^/]+\/docs\/recipe-first-login\.md/,
	);
});
