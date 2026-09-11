/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Issue #407 — scaffold hardening from the v0.10.0 release-cut audit.
 *
 * These pin the parts of the scaffold that are checkable from inside the
 * repository. The scaffold is the artifact an operator actually deploys, and
 * every one of these was invisible until someone read the file: the container
 * install losing an allowlist, the dev compose dialling a Redis that is not
 * there, and one `git add .` committing the signing key.
 */

import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { type AppConfig, AppConfigSchema } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";

const standaloneDir = fileURLToPath(new URL("../..", import.meta.url));
const configDir = fileURLToPath(new URL("../../config", import.meta.url));
const read = (rel: string): string => readFileSync(`${standaloneDir}${rel}`, "utf8");

/**
 * The `environment:` entries of a compose file's `app` service, as the
 * environment the container would actually see.
 *
 * A hand-rolled reader rather than a YAML dependency: these two files are
 * fixed-shape artifacts in this repository, the block is flat `KEY: value`
 * scalars, and adding a parser to the template's dependency tree to read its
 * own scaffold would be a strange thing to ship to operators.
 *
 * Compose's `${VAR:?err}` required-variable form resolves from the operator's
 * shell or `.env`, so there is no literal value to record — the key is mapped
 * to `null`, which is the point of that form and what the assertions below
 * check for.
 */
function composeAppEnvironment(rel: string): Map<string, string | null> {
	const lines = read(rel).split("\n");
	const start = lines.findIndex((line) => /^\s{4}environment:\s*$/.test(line));
	const env = new Map<string, string | null>();
	if (start === -1) return env;
	for (const line of lines.slice(start + 1)) {
		if (line.trim() === "" || /^\s*#/.test(line)) continue;
		// The block ends at the first line indented no further than its own key.
		if (!/^\s{6}\S/.test(line)) break;
		const match = /^\s{6}([A-Z][A-Z0-9_]*):\s*(.*)$/.exec(line);
		if (!match) continue;
		const raw = (match[2] as string).trim().replace(/^["']|["']$/g, "");
		env.set(match[1] as string, /^\$\{[A-Z][A-Z0-9_]*:\?/.test(raw) ? null : raw);
	}
	return env;
}

/** Resolve the shipped config layers under a given environment, as `src/app.mts` does. */
function resolveWith(env: Record<string, string>, configEnv = "production"): AppConfig {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, configEnv);
	return validate(
		parseFile(envConfPath, { env })
			.withFallback(parseFile(applicationConfPath, { env }))
			.withFallback(parseFile(resolveLibraryReferenceConfPath(), { env })),
		AppConfigSchema,
	);
}

/**
 * A compose file's `environment:` block, plus the secrets no compose file
 * carries (they come from `.env` or a compose secret) — the environment the
 * process would boot under.
 *
 * The key material follows what the file itself says: the production compose
 * points the EdDSA key paths at its mounted secrets, so leave the default
 * algorithm alone; the dev compose supplies no key at all, so give it the
 * HS256 shape, whose `.strict()` union member is exactly why the two cannot
 * share one map.
 */
function bootableEnv(rel: string): Record<string, string> {
	const env: Record<string, string> = {
		OAUTH_JWT_ISSUER: "https://auth.test",
		SESSION_SECRET: "scaffold-assets-compose-session.at-least-32-bytes.ok",
	};
	for (const [key, value] of composeAppEnvironment(rel)) {
		if (value !== null) env[key] = value;
	}
	if (env.OAUTH_JWT_PRIVATE_KEY_PATH === undefined) {
		env.OAUTH_JWT_ALGORITHM = "HS256";
		env.OAUTH_JWT_SECRET = "scaffold-assets-compose.at-least-32-bytes.ok";
	}
	return env;
}

describe("#407 — the Dockerfile installs with everything pnpm needs", () => {
	it("copies pnpm-workspace.yaml into the deps stage", () => {
		// `create-auth-provider` generates it to carry the bcrypt
		// `onlyBuiltDependencies` allowlist, because pnpm >= 10.29 reads that
		// setting ONLY from this file — in single-package projects too (#360).
		// A deps stage that copies `package.json` and the lockfile but not this
		// runs allowlist-less, which re-creates #360 the day an alpine prebuild
		// is missing and bcrypt has to compile.
		const dockerfile = read("/Dockerfile");
		const depsStage = dockerfile.slice(
			dockerfile.indexOf("FROM node-base AS deps"),
			dockerfile.indexOf("FROM", dockerfile.indexOf("FROM node-base AS deps") + 1),
		);
		// Matched as a COPY instruction, not as a substring of the stage: the
		// comment above that COPY names the file too, so a substring check
		// would keep passing if the instruction regressed and the comment
		// stayed — which is the failure this test exists to catch.
		const copyLines = depsStage
			.split("\n")
			.filter((line) => /^COPY\b/.test(line.trim()) && !line.trim().startsWith("#"));
		expect(copyLines.some((line) => /\bpnpm-workspace\.yaml\b/.test(line))).toBe(true);
	});
});

describe("#407 — the dev compose can reach every Redis it configures", () => {
	it("sets every *_REDIS_URL the template config reads", () => {
		// The template's application.conf substitutes several Redis URLs, each
		// defaulting to `redis://localhost:6379` — which inside the container is
		// the container itself. `.env.example` is what the compose file loads,
		// so a URL missing from it is a boot that dials nothing.
		const conf = read("/config/application.conf");
		const declared = [...conf.matchAll(/\$\{\?([A-Z0-9_]*REDIS_URL)\}/g)].map((m) => m[1]);
		expect(declared.length).toBeGreaterThan(0);

		const env = read("/.env.example");
		const missing = [...new Set(declared)].filter(
			(name) => !new RegExp(`^${name}=`, "m").test(env),
		);
		expect(missing).toEqual([]);
	});
});

describe("#407 — the scaffold does not invite committing its own secrets", () => {
	it("ships a .gitignore", () => {
		// Without one, the first `git add .` in a scaffolded project commits
		// `.env` and `jwt-private.pem` — both of which the README tells the
		// operator to create right there.
		expect(existsSync(`${standaloneDir}/.gitignore`)).toBe(true);
	});

	it("ignores the files the scaffold's own setup steps create", () => {
		const ignored = read("/.gitignore");
		for (const pattern of [".env", "*.pem", "node_modules", "dist"]) {
			expect(ignored).toContain(pattern);
		}
	});

	it("keeps .env.example tracked — it is the documentation", () => {
		// A bare `.env*` would take the example with it, which is the mistake
		// this pins against.
		expect(read("/.gitignore")).toMatch(/^!\.env\.example$/m);
	});
});

describe("#407 — the production compose matches the topology it documents", () => {
	it("does not publish the app port on every interface", () => {
		// The README says to keep `/metrics` off the public listener and the
		// file assumes TLS is terminated in front, so a bare "3000:3000"
		// contradicts both — it binds 0.0.0.0 on the host.
		const compose = read("/docker-compose.production.yml");
		expect(compose).not.toMatch(/^\s*-\s*"3000:3000"\s*$/m);
		expect(compose).toMatch(/127\.0\.0\.1:3000:3000/);
	});
});

describe("the compose files put a store and its lifetime-sibling on the same backend", () => {
	// The production compose set `SESSION_STORAGE_TYPE: redis` and left
	// `USER_SESSION_STORES_ADAPTER` at its `memory` default. express-session
	// then survives a restart and the `UserSession` it points at does not, so
	// every browser comes back `isAuthenticated` with nothing behind it and
	// /authorize loops until the cookie is deleted by hand.
	//
	// `DEPLOYMENT_MODE: single` is silent about this on purpose — the replica
	// guard answers "can these stores be shared", not "do these two stores have
	// the same lifetime" — so nothing but this assertion stands behind it.
	for (const file of ["/docker-compose.production.yml", "/docker-compose.yml"]) {
		it(`${file} keeps the user-session stores with the express-session store`, () => {
			const config = resolveWith(bootableEnv(file));
			// Resolved through the real config layers, not read off the file:
			// what matters is the value the process ends up with, whether the
			// compose stated it or `config/application.conf` did.
			expect(config.session.storage?.type).toBe("redis");
			expect(config.userSessionStores?.adapter).toBe("redis");
		});
	}

	it("the production compose leaves no store on memory while a sibling is on Redis", () => {
		const config = resolveWith(bootableEnv("/docker-compose.production.yml"));
		// Every store whose records must outlive one process. The federation
		// token store is deliberately absent: this template ships every
		// federation disabled, so nothing writes to it, and turning it on needs
		// an AES key the compose file must not invent.
		expect(config.session.storage?.type).toBe("redis");
		expect(config.userSessionStores?.adapter).toBe("redis");
		expect(config.oauth.code?.adapter).toBe("redis");
		expect(config.accessTokenDenylist?.adapter).toBe("redis");
		expect(config.rateLimiter?.adapter).toBe("redis");
	});
});

describe("the production compose refuses to guess HTTP_TRUST_PROXY", () => {
	it("names the variable and supplies no default", () => {
		// Without it the Secure cookie is never set, the CSRF origin check 403s
		// every browser POST, and every IP-keyed rate limit shares one bucket.
		// With a baked-in default it would silently trust a hop the operator
		// never chose. The `${VAR:?err}` form is the only reading that is
		// neither: compose refuses to start until the operator names their edge.
		const compose = composeAppEnvironment("/docker-compose.production.yml");
		expect(compose.has("HTTP_TRUST_PROXY")).toBe(true);
		expect(compose.get("HTTP_TRUST_PROXY")).toBeNull();
		expect(read("/docker-compose.production.yml")).not.toMatch(
			/HTTP_TRUST_PROXY:\s*(true|false)\b/,
		);
	});

	it("is offered in .env.example with no value", () => {
		// The compose reads it from `.env`, which the operator copies from here.
		expect(read("/.env.example")).toMatch(/^HTTP_TRUST_PROXY=$/m);
	});
});

describe("#407 — the two READMEs agree on security advice", () => {
	it("does not recommend HTTP_TRUST_PROXY=true in the Japanese README", () => {
		// #292 made `trust proxy` a CIDR/hop policy precisely because `true`
		// means "believe the leftmost forwarded entry from whoever opened the
		// connection". The English README warns against it; the Japanese one
		// still recommended it, so the two disagreed on which is safe.
		expect(read("/README.ja.md")).not.toMatch(/HTTP_TRUST_PROXY=true/);
	});
});

/**
 * Issue #512 — the suite that ships with a scaffolded project has to be green
 * in that project, not only in this workspace.
 *
 * A scaffold installs `@o3co/auth-provider-*` from npm, where the packages sit
 * under `node_modules` and vitest externalizes them: Node loads them natively
 * and their own `import "ioredis"` / `import "redis"` never meet the
 * `vi.mock` registry. In this workspace the same packages are symlinks to
 * source outside `node_modules`, vitest inlines them, and the mocks apply —
 * which is how replica-safety.test.mts stayed green here while dialling
 * `redis.test` for real in every scaffold. The second half is `make test`:
 * it runs this suite inside the `test` image, where a file the Dockerfile
 * never copied simply does not exist.
 */
describe("#512 — the shipped suite is green outside this repository", () => {
	it("runs the published packages through vitest, so module mocks reach them", async () => {
		// The config is loaded, not grepped: what matters is the value vitest
		// resolves, and a `server.deps.inline` naming the wrong package would
		// satisfy a substring check just as well.
		const configPath = fileURLToPath(new URL("../../vitest.config.mts", import.meta.url));
		const { default: config } = (await import(configPath)) as {
			default: {
				test?: { server?: { deps?: { inline?: ReadonlyArray<string | RegExp> | true } } };
			};
		};
		const inline = config.test?.server?.deps?.inline;
		expect(inline).toBeDefined();
		if (inline === true) return;
		for (const name of [
			"@o3co/auth-provider-core",
			"@o3co/auth-provider-redis",
			"@o3co/auth-provider-session",
		]) {
			expect(
				(inline ?? []).some((m) => (m instanceof RegExp ? m.test(name) : m === name)),
				`${name} is not inlined`,
			).toBe(true);
		}
	});

	/**
	 * Every file this suite reads from the project root. `config/` and `src/`
	 * reach the image through the builder stage; these do not, so the `test`
	 * stage has to bring them — and `.dockerignore` has to let them into the
	 * build context first.
	 */
	const READ_FROM_THE_PROJECT_ROOT = [
		"Dockerfile",
		".dockerignore",
		".env.example",
		".gitignore",
		"README.md",
		"README.ja.md",
		"docker-compose.yml",
		"docker-compose.production.yml",
	] as const;

	it("reads only files the template actually ships", () => {
		for (const file of READ_FROM_THE_PROJECT_ROOT) {
			expect(existsSync(`${standaloneDir}${file}`), file).toBe(true);
		}
	});

	it("copies each of them into the image the `test` target runs", () => {
		const copied = copiedIntoStage(read("/Dockerfile"), "test");
		for (const file of READ_FROM_THE_PROJECT_ROOT) {
			expect(copied.has(file), `${file} is not copied into the test image`).toBe(true);
		}
	});

	it("lets each of them through .dockerignore", () => {
		const dockerignore = read("/.dockerignore");
		for (const file of READ_FROM_THE_PROJECT_ROOT) {
			expect(
				dockerignoreExcludes(dockerignore, file),
				`${file} is excluded from the build context`,
			).toBe(false);
		}
	});
});

/**
 * The build-context sources every `COPY` in `stage` and its ancestors brings
 * into the image. `COPY --from=` is skipped — it reads another stage, not
 * the context — and `--chown` / other flags are dropped. Sources are
 * normalised to the bare entry name (`./config/` → `config`).
 */
function copiedIntoStage(dockerfile: string, stage: string): Set<string> {
	const stages = new Map<string, { parent: string; sources: string[] }>();
	let current: { parent: string; sources: string[] } | undefined;
	// Continuation lines are joined first, so a multi-line instruction reads
	// as one.
	for (const line of dockerfile.replace(/\\\n/g, " ").split("\n")) {
		const text = line.trim();
		if (text === "" || text.startsWith("#")) continue;
		const from = /^FROM\s+(\S+)(?:\s+AS\s+(\S+))?/i.exec(text);
		if (from) {
			const parent = from[1] as string;
			current = { parent, sources: [] };
			stages.set(from[2] ?? parent, current);
			continue;
		}
		if (!current || !/^COPY\b/i.test(text)) continue;
		const args = text.split(/\s+/).slice(1);
		if (args.some((a) => a.startsWith("--from="))) continue;
		const operands = args.filter((a) => !a.startsWith("--"));
		for (const source of operands.slice(0, -1)) {
			current.sources.push(source.replace(/^\.\//, "").replace(/\/$/, ""));
		}
	}
	const copied = new Set<string>();
	for (let name: string | undefined = stage; name !== undefined; ) {
		const s = stages.get(name);
		if (!s) break;
		for (const source of s.sources) copied.add(source);
		name = s.parent;
	}
	return copied;
}

/**
 * Whether `.dockerignore` keeps a root-level entry out of the build context.
 * The last matching pattern wins and a leading `!` re-includes; `*` and `?`
 * stop at a `/` while `**` does not — the subset of Docker's matching that
 * root-level file names exercise.
 */
function dockerignoreExcludes(dockerignore: string, file: string): boolean {
	let excluded = false;
	for (const raw of dockerignore.split("\n")) {
		const line = raw.trim();
		if (line === "" || line.startsWith("#")) continue;
		const negated = line.startsWith("!");
		const pattern = negated ? line.slice(1) : line;
		// `**` is split out first so the single-`*` rewrite cannot see it.
		const segment = (s: string): string =>
			s
				.replace(/[.+^${}()|[\]\\]/g, "\\$&")
				.replace(/\*/g, "[^/]*")
				.replace(/\?/g, "[^/]");
		const regex = new RegExp(`^${pattern.split("**").map(segment).join(".*")}$`);
		if (regex.test(file)) excluded = !negated;
	}
	return excluded;
}
