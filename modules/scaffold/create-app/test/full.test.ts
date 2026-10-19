import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { full, optIns } from "@mod/combinations";
import { parseString } from "@o3co/ts.hocon";
import { expect, it, vi } from "vitest";
import { generate, trialSettings } from "../src/contract.ts";
import {
	boot,
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
	expect(Object.keys(pkg.dependencies)).toEqual([kernel, ...modules]);
	expect(pkg.scripts).toEqual({
		start: "node --env-file-if-exists=.env src/main.ts",
		reseal: "node --env-file-if-exists=.env src/reseal.ts",
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
	expect(docker).toMatch(/^FROM node:2[4-9]\.\d+\.\d+-[a-z]+@sha256:[0-9a-f]{64} AS base$/m);
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
	const env = await configured(target, { deployment: "single", redisUrl: "redis://127.0.0.1:1" });
	const run = boot(target, "config/local.conf,config/application.conf", env);
	expect(run.status, run.stderr).toBe(78);
	expect(run.refused, run.stderr).toEqual(["redis.url"]);
});

it("makes the full template from the command with features added, and the listed packages' app as before", async () => {
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
	expect(existsSync(join(parent, "listed", "Dockerfile"))).toBe(false);
	for (const args of [
		[join(parent, "both"), "--add", "@mod/device-grant", "@mod/http"],
		[join(parent, "sink"), "--sink", "@mod/log-stdout"],
		[],
	]) {
		expect(cli(...args).status, args.join(" ")).toBe(64);
	}
});

it("writes the clients given into the trial's one clients.registered, and no block for none or for clients left", async () => {
	const target = await generated();
	const redisUrl = "redis://127.0.0.1:1";
	const clients = [
		{ id: "app", kind: "public", method: "none" },
		{
			id: "svc",
			kind: "confidential",
			method: "client_secret_basic",
			sections: { x: { "a.b": "${c}" } },
		},
	];
	const given = await trialSettings(target, { redisUrl, clients });
	expect(parseString(given.local).get("clients.registered")).toEqual(clients);
	for (const settings of [{ redisUrl }, { redisUrl, clients, leave: ["clients"] }]) {
		expect((await trialSettings(target, settings)).local).not.toMatch(/^clients /m);
	}
});

it("gives signer-keys-http an issuer and keys-url of the trial's own, its host allowed", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-trial-"));
	mkdirSync(join(target, "src"));
	await writeFile(
		join(target, "src", "main.ts"),
		'import o from "@mod/outbound/module";\nimport s from "@mod/signer-keys-http/module";\n',
	);
	const local = parseString(
		(await trialSettings(target, { redisUrl: "redis://127.0.0.1:1" })).local,
	);
	expect(local.get("signer-keys-http")).toEqual({
		issuer: "https://devices.example.invalid",
		"keys-url": "https://ledger.example.invalid/signer-keys",
	});
	expect(local.get("outbound.allow")).toEqual(["ledger.example.invalid"]);
	expect(local.get("jwt-bearer")).toBeUndefined();
});

it("gives mfa-witness-http three URLs of the trial's own at one origin, its host allowed, and a credential", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-trial-"));
	mkdirSync(join(target, "src"));
	await writeFile(
		join(target, "src", "main.ts"),
		'import o from "@mod/outbound/module";\nimport w from "@mod/mfa-witness-http/module";\n',
	);
	const trial = await trialSettings(target, { redisUrl: "redis://127.0.0.1:1" });
	const local = parseString(trial.local);
	expect(local.get("mfa-witness-http")).toEqual({
		"read-url": "https://ledger.example.invalid/mfa-witness/read",
		"enroll-url": "https://ledger.example.invalid/mfa-witness/enroll",
		"clear-url": "https://ledger.example.invalid/mfa-witness/clear",
	});
	expect(local.get("outbound.allow")).toEqual(["ledger.example.invalid"]);
	expect(trial.env.MFA_WITNESS_HTTP_CREDENTIAL).toMatch(/^[A-Za-z0-9_-]{43}$/);
});

it("names signer-keys-http's issuer among jwt-bearer's issuers where both are composed, its keys contributed", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-trial-"));
	mkdirSync(join(target, "src"));
	await writeFile(
		join(target, "src", "main.ts"),
		[
			'import o from "@mod/outbound/module";',
			'import j from "@mod/jwt-bearer/module";',
			'import s from "@mod/signer-keys-http/module";',
			"",
		].join("\n"),
	);
	const redisUrl = "redis://127.0.0.1:1";
	const local = parseString((await trialSettings(target, { redisUrl })).local);
	expect(local.get("jwt-bearer.issuers")).toEqual([
		{ issuer: "https://devices.example.invalid", subject: "as-is" },
	]);
	const left = parseString(
		(await trialSettings(target, { redisUrl, leave: ["jwt-bearer"] })).local,
	);
	expect(left.get("jwt-bearer")).toBeUndefined();
});

it("gives subject-revocation-http a fresh credential, its sources and a trusted proxy no request comes through", async () => {
	const target = await mkdtemp(join(tmpdir(), "create-app-trial-"));
	mkdirSync(join(target, "src"));
	await writeFile(
		join(target, "src", "main.ts"),
		[
			'import h from "@mod/http/module";',
			'import r from "@mod/subject-revocation-http/module";',
			"",
		].join("\n"),
	);
	const redisUrl = "redis://127.0.0.1:1";
	const given = await trialSettings(target, { redisUrl });
	const local = parseString(given.local);
	expect(local.get("subject-revocation-http.sources")).toEqual(["192.0.2.0/24"]);
	expect(local.get("http.trusted-proxies")).toEqual(["192.0.2.1"]);
	const credential = given.env.SUBJECT_REVOCATION_HTTP_CREDENTIAL ?? "";
	expect(Buffer.from(credential, "base64url").length).toBe(32);
	const again = await trialSettings(target, { redisUrl });
	expect(again.env.SUBJECT_REVOCATION_HTTP_CREDENTIAL).not.toBe(credential);
	const left = parseString(
		(await trialSettings(target, { redisUrl, leave: ["http", "subject-revocation-http"] })).local,
	);
	expect(left.get("http")).toBeUndefined();
	expect(left.get("subject-revocation-http")).toBeUndefined();
});

it("gives exchange-id-tokens one upstream for a client of the trial's own, registered beside the clients given", async () => {
	const redisUrl = "redis://127.0.0.1:1";
	const given = [{ id: "app", kind: "public", method: "none" }];
	/** An app whose entry imports these modules, as far as the trial settings read it. */
	const importing = async (names: readonly string[]) => {
		const target = await mkdtemp(join(tmpdir(), "create-app-trial-"));
		mkdirSync(join(target, "src"));
		const lines = names.map((name, i) => `import m${i} from "@mod/${name}/module";`);
		await writeFile(join(target, "src", "main.ts"), `${lines.join("\n")}\n`);
		return target;
	};
	const target = await importing(["clients", "exchange-id-tokens"]);
	const local = parseString((await trialSettings(target, { redisUrl, clients: given })).local);
	const registered = local.get("clients.registered") as { id: string }[];
	expect(registered.map((c) => c.id)).toEqual(["app", "trial-id-tokens"]);
	expect(local.get("exchange-id-tokens.google.clients")).toEqual({
		"trial-id-tokens": { audiences: ["trial-google-server-client-id"] },
	});
	const plain = (await trialSettings(await importing(["clients"]), { redisUrl, clients: given }))
		.local;
	expect(plain).not.toMatch(/^exchange-id-tokens /m);
	expect(parseString(plain).get("clients.registered")).toEqual(given);
});

it("gives a generated app trial settings by its own modules, with hosts under .invalid and keys made fresh", async () => {
	const target = await generated();
	const [one, other] = [
		await trialSettings(target, { redisUrl: "redis://127.0.0.1:1", port: 1234 }),
		await trialSettings(target, { redisUrl: "redis://127.0.0.1:1", deployment: "multi" }),
	];
	expect(one.local).toMatch(/^kernel \{ deployment = single \}$/m);
	expect(other.local).toMatch(/^kernel \{ deployment = multi \}$/m);
	expect(one.local).toContain("port = 1234");
	expect(one.env.KEYS_SIGNING_PRIVATE_KEY).not.toBe(other.env.KEYS_SIGNING_PRIVATE_KEY);
	const hosts = [
		...`${one.local}${Object.values(one.env).join("\n")}`.matchAll(
			/[a-z0-9-]+(?:\.[a-z0-9-]+)+(?=[/:"\s,\]]|$)/gm,
		),
	]
		.map((m) => m[0])
		.filter((host) => /[a-z]/.test(host) && !/^\d/.test(host));
	expect(hosts.length).toBeGreaterThan(0);
	for (const host of hosts) expect(host, host).toMatch(/\.invalid$/);
});

it("leaves out of the trial settings every variable and block of the sections the caller names", async () => {
	const target = await generated();
	const all = await trialSettings(target, { redisUrl: "redis://127.0.0.1:1" });
	const left = await trialSettings(target, {
		redisUrl: "redis://127.0.0.1:1",
		leave: ["keys", "http"],
	});
	expect(Object.keys(all.env).filter((name) => name.startsWith("KEYS_")).length).toBeGreaterThan(0);
	expect(Object.keys(left.env).filter((name) => name.startsWith("KEYS_"))).toEqual([]);
	expect(Object.keys(left.env).sort()).toEqual(
		Object.keys(all.env)
			.filter((name) => !name.startsWith("KEYS_"))
			.sort(),
	);
	expect(all.local).toMatch(/^http \{/m);
	expect(left.local).not.toMatch(/^http \{/m);
	expect(left.local).toMatch(/^kernel \{/m);
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

it("merges the hosts a caller adds into the one trial outbound block, and makes mfa optional where it is composed", async () => {
	const target = await generated();
	const { local } = await trialSettings(target, {
		redisUrl: "redis://127.0.0.1:1",
		allow: ["sink.example.invalid"],
		plainLoopback: ["127.0.0.1:4318"],
	});
	expect(local.match(/^outbound \{/gm)).toHaveLength(1);
	expect(local).toMatch(
		/^outbound \{ allow = \[ledger\.example\.invalid, audit\.example\.invalid, sink\.example\.invalid\], plain-loopback = \["127\.0\.0\.1:4318"\] \}$/m,
	);
	expect(local).toMatch(/^mfa \{ mode = optional \}$/m);
	const left = await trialSettings(target, {
		redisUrl: "redis://127.0.0.1:1",
		leave: ["mfa", "outbound"],
	});
	expect(left.local).not.toMatch(/^(mfa|outbound) \{/m);
});

it("gives webauthn the trial's public origin where it is composed, and leaves it to a caller deciding it", async () => {
	const withPasskeys = await generated(["@mod/webauthn"]);
	const { local } = await trialSettings(withPasskeys, { redisUrl: "redis://127.0.0.1:1" });
	expect(local).toMatch(
		/^webauthn \{ rp-id = login\.example\.invalid, rp-name = "Trial", origins = \["https:\/\/login\.example\.invalid"\] \}$/m,
	);
	const left = await trialSettings(withPasskeys, {
		redisUrl: "redis://127.0.0.1:1",
		leave: ["webauthn"],
	});
	expect(left.local).not.toMatch(/^webauthn \{/m);
	expect(
		(await trialSettings(await generated(), { redisUrl: "redis://127.0.0.1:1" })).local,
	).not.toMatch(/^webauthn \{/m);
});

it("reads the modules an app composes from its entry, whatever names it imports them under", async () => {
	const target = mkdtempSync(join(tmpdir(), "trial-"));
	mkdirSync(join(target, "src"));
	writeFileSync(join(target, "package.json"), JSON.stringify({ dependencies: {} }));
	writeFileSync(
		join(target, "src/main.ts"),
		[
			'import { assemble } from "@o3co/auth-provider-foundation/kernel";',
			'import m0 from "@o3co/auth-provider-oauth/authorize/module";',
			'import m1 from "@o3co/auth-provider-foundation/http/module";',
		].join("\n"),
	);
	const { local } = await trialSettings(target, { redisUrl: "redis://127.0.0.1:1" });
	expect(local).toContain("authorize { login-page");
	expect(local).toContain("http { public-origin");
	expect(local).not.toContain("users-http");
});
