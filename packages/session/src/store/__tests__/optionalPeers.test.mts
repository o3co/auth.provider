/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * The Redis session store's two libraries, `redis` and `connect-redis`, are
 * optional peer dependencies: a deployment on `session.storage.type = "memory"`
 * installs neither and boots, and one on `"redis"` that did not install them
 * fails boot with a message naming the missing package and the fix.
 *
 * Each boot runs in a child Node process whose resolver cannot find the
 * packages a case hides (fixtures/hide-packages.mjs): Node's own resolver and
 * its own error, not a mock of either library, over the built package a
 * consumer installs. So a static import of either library, anywhere the
 * package entry reaches, fails the memory case at import time. The package
 * must be built first (`pnpm run build`), as for every test that imports a
 * sibling.
 *
 * The hook needs `module.registerHooks` (Node >= 22.15 or >= 23.5), which the
 * package's `engines` floor predates: on an older Node the suite fails at once,
 * saying so, rather than with a child that printed nothing. Each case starts a
 * Node process that loads the package graph, so a case gets 60 seconds, not
 * the workspace's 20: on a loaded machine the process alone has taken longer.
 */

import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import * as nodeModule from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_DIR = resolve(HERE, "../../..");
const HIDE_PACKAGES = pathToFileURL(join(HERE, "fixtures/hide-packages.mjs")).href;
const BOOT = join(HERE, "fixtures/boot-session-store.mjs");
const PEERS = ["redis", "connect-redis"] as const;
const CHILD_TIMEOUT = 60_000;

type Outcome = { readonly booted: true } | { readonly booted: false; readonly message: string };

/**
 * Run Node with the hiding hook loaded, and parse the last `RESULT <json>` line
 * it printed. NODE_PATH, which pnpm sets for the scripts it runs, is left out:
 * CommonJS resolution searches it from anywhere, so a package it holds could
 * not be hidden from `require`.
 */
async function run<T>(args: readonly string[], env: Record<string, string>): Promise<T> {
	const { NODE_PATH: _searchedByRequire, ...inherited } = process.env;
	const { stdout } = await promisify(execFile)(
		process.execPath,
		["--import", HIDE_PACKAGES, ...args],
		{ cwd: PACKAGE_DIR, env: { ...inherited, ...env }, timeout: CHILD_TIMEOUT - 5_000 },
	);
	const line = stdout
		.split("\n")
		.reverse()
		.find((l) => l.startsWith("RESULT "));
	if (line === undefined) throw new Error(`the child printed no RESULT line:\n${stdout}`);
	return JSON.parse(line.slice("RESULT ".length)) as T;
}

const boot = (type: "memory" | "redis", hidden: readonly string[]) =>
	run<Outcome>([BOOT], { SESSION_STORAGE_TYPE: type, HIDE_PACKAGES: hidden.join(",") });

/** How `require` and `import` each fare with `redis` hidden, and with `connect-redis` not. */
const PROBE = `
import { createRequire } from "node:module";
const require = createRequire(process.cwd() + "/package.json");
const outcome = async (load) => { try { await load(); return "loaded"; } catch (err) { return err.code; } };
console.log("RESULT " + JSON.stringify({
	requireHidden: await outcome(() => require("redis")),
	importHidden: await outcome(() => import("redis")),
	requireOther: await outcome(() => require("connect-redis")),
	importOther: await outcome(() => import("connect-redis")),
}));
`;

describe("the Redis session store's libraries are optional peers", () => {
	beforeAll(() => {
		if (!("registerHooks" in nodeModule)) {
			throw new Error(
				`these tests hide packages with module.registerHooks, which Node ${process.version} lacks: run them on Node >= 22.15 or >= 23.5`,
			);
		}
		if (!existsSync(join(PACKAGE_DIR, "dist/index.mjs"))) {
			throw new Error("build @o3co/auth-provider-session first: `pnpm run build`");
		}
	});

	it(
		"hides a package from require and import alike, and nothing else",
		async () => {
			expect(await run(["--input-type=module", "-e", PROBE], { HIDE_PACKAGES: "redis" })).toEqual({
				requireHidden: "MODULE_NOT_FOUND",
				importHidden: "ERR_MODULE_NOT_FOUND",
				requireOther: "loaded",
				importOther: "loaded",
			});
		},
		CHILD_TIMEOUT,
	);

	it("declares redis and connect-redis as optional peers, never as dependencies", () => {
		const manifest = JSON.parse(readFileSync(join(PACKAGE_DIR, "package.json"), "utf8")) as {
			dependencies?: Record<string, string>;
			peerDependencies?: Record<string, string>;
			peerDependenciesMeta?: Record<string, { optional?: boolean }>;
			devDependencies?: Record<string, string>;
		};
		for (const name of PEERS) {
			expect(manifest.dependencies?.[name], `dependencies["${name}"]`).toBeUndefined();
			expect(manifest.peerDependencies?.[name], `peerDependencies["${name}"]`).toBeDefined();
			expect(manifest.peerDependenciesMeta?.[name]?.optional, `${name} optional`).toBe(true);
			// The package's own build and tests still need them.
			expect(manifest.devDependencies?.[name], `devDependencies["${name}"]`).toBeDefined();
		}
	});

	it(
		"boots a memory-only composition with neither package installed",
		async () => {
			expect(await boot("memory", PEERS)).toEqual({ booted: true });
		},
		CHILD_TIMEOUT,
	);

	it.each([[["redis"]], [["connect-redis"]], [["redis", "connect-redis"]]])(
		"refuses a redis store with %j missing, naming what is missing and the fix",
		async (hidden) => {
			const outcome = await boot("redis", hidden);
			expect(outcome.booted).toBe(false);
			if (outcome.booted) return;
			const missing = hidden.map((name) => `"${name}"`).join(" and ");
			expect(outcome.message).toContain('session.storage.type is "redis"');
			expect(outcome.message).toContain(
				`${missing} ${hidden.length === 1 ? "is" : "are"} not installed`,
			);
			expect(outcome.message).toContain("npm install redis@^6.2.1 connect-redis@^10.0.0");
		},
		CHILD_TIMEOUT,
	);
});
