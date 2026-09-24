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
 */

import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_DIR = resolve(HERE, "../../..");
const HIDE_PACKAGES = pathToFileURL(join(HERE, "fixtures/hide-packages.mjs")).href;
const BOOT = join(HERE, "fixtures/boot-session-store.mjs");
const PEERS = ["redis", "connect-redis"] as const;

type Outcome = { readonly booted: true } | { readonly booted: false; readonly message: string };

async function boot(type: "memory" | "redis", hidden: readonly string[]): Promise<Outcome> {
	const { stdout } = await promisify(execFile)(
		process.execPath,
		["--import", HIDE_PACKAGES, BOOT],
		{
			cwd: PACKAGE_DIR,
			env: { ...process.env, SESSION_STORAGE_TYPE: type, HIDE_PACKAGES: hidden.join(",") },
			timeout: 30_000,
		},
	);
	const line = stdout
		.split("\n")
		.reverse()
		.find((l) => l.startsWith("RESULT "));
	if (line === undefined) throw new Error(`the boot printed no RESULT line:\n${stdout}`);
	return JSON.parse(line.slice("RESULT ".length)) as Outcome;
}

describe("the Redis session store's libraries are optional peers", () => {
	beforeAll(() => {
		if (!existsSync(join(PACKAGE_DIR, "dist/index.mjs"))) {
			throw new Error("build @o3co/auth-provider-session first: `pnpm run build`");
		}
	});

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

	it("boots a memory-only composition with neither package installed", async () => {
		expect(await boot("memory", PEERS)).toEqual({ booted: true });
	});

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
			expect(outcome.message).toContain("npm install redis connect-redis");
		},
	);
});
