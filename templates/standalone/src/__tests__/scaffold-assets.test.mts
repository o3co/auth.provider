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
 * Pins the parts of the scaffold that are checkable from inside the
 * repository. The scaffold is the artifact an operator actually deploys, and
 * a mistake in it stays invisible until someone reads the file: the container
 * install losing an allowlist, the dev compose dialling a Redis that is not
 * there, one `git add .` committing the signing key.
 */

import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { type AppConfig, AppConfigSchema, coreReference } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { resolveConfigPaths } from "../configPath.mjs";
import { templateReference } from "../modules.mjs";

const standaloneDir = fileURLToPath(new URL("../..", import.meta.url));
const configDir = fileURLToPath(new URL("../../config", import.meta.url));
const read = (rel: string): string => readFileSync(`${standaloneDir}${rel}`, "utf8");

/**
 * The `environment:` entries of a compose file's `app` service, as the
 * environment the container would actually see. Hand-rolled rather than a
 * YAML dependency: both files are fixed-shape, the block is flat `KEY: value`
 * scalars, and the template should not ship a parser to read its own
 * scaffold. Compose's `${VAR:?err}` required-variable form resolves from the
 * operator's shell or `.env`, so its key is mapped to `null`.
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
			.withFallback(parseFile(fileURLToPath(templateReference()), { env }))
			.withFallback(parseFile(fileURLToPath(coreReference()), { env })),
		AppConfigSchema,
	);
}

/**
 * A compose file's `environment:` block, plus the secrets no compose file
 * carries (they come from `.env` or a compose secret) — the environment the
 * process would boot under. The production compose points the EdDSA key
 * paths at its mounted secrets, so the default algorithm stays; the dev
 * compose supplies no key, so it gets the HS256 shape, whose `.strict()`
 * union member is why the two cannot share one map.
 */
function bootableEnv(rel: string): Record<string, string> {
	const env: Record<string, string> = {
		OAUTH_JWT_ISSUER: "https://auth.test",
		SESSION_STORE_SECRET: "scaffold-assets-compose-session.at-least-32-bytes.ok",
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

describe("the Dockerfile installs with everything pnpm needs", () => {
	it("copies pnpm-workspace.yaml into the deps stage", () => {
		// `create-auth-provider` generates it to carry the bcrypt
		// `onlyBuiltDependencies` allowlist, because pnpm >= 10.29 reads that
		// setting ONLY from this file — in single-package projects too. A deps
		// stage without it runs allowlist-less, which leaves bcrypt unbuilt the
		// day an alpine prebuild is missing and it has to compile.
		const dockerfile = read("/Dockerfile");
		const depsStage = dockerfile.slice(
			dockerfile.indexOf("FROM node-base AS deps"),
			dockerfile.indexOf("FROM", dockerfile.indexOf("FROM node-base AS deps") + 1),
		);
		// Matched as a COPY instruction, not as a substring of the stage: the
		// comment above that COPY names the file too, so a substring check
		// would keep passing without the instruction.
		const copyLines = depsStage
			.split("\n")
			.filter((line) => /^COPY\b/.test(line.trim()) && !line.trim().startsWith("#"));
		expect(copyLines.some((line) => /\bpnpm-workspace\.yaml\b/.test(line))).toBe(true);
	});
});

describe("the dev compose can reach every Redis it configures", () => {
	it("sets every *_REDIS_URL the template config reads", () => {
		// The template's application.conf and its own reference.conf substitute
		// several Redis URLs, each defaulting to `redis://localhost:6379` —
		// which inside the container is the container itself. `.env.example` is
		// what the compose file loads, so a URL missing from it is a boot that
		// dials nothing.
		const conf = read("/config/application.conf") + read("/config/reference.conf");
		const declared = [...conf.matchAll(/\$\{\?([A-Z0-9_]*REDIS_URL)\}/g)].map((m) => m[1]);
		expect(declared.length).toBeGreaterThan(0);

		const env = read("/.env.example");
		const missing = [...new Set(declared)].filter(
			(name) => !new RegExp(`^${name}=`, "m").test(env),
		);
		expect(missing).toEqual([]);
	});
});

describe("the scaffold does not invite committing its own secrets", () => {
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

describe("the production compose matches the topology it documents", () => {
	it("does not publish the app port on every interface", () => {
		// The README says to keep `/metrics` off the public listener and the
		// file assumes TLS is terminated in front, so a bare "3000:3000"
		// contradicts both — it binds 0.0.0.0 on the host.
		const compose = read("/docker-compose.production.yml");
		expect(compose).not.toMatch(/^\s*-\s*"3000:3000"\s*$/m);
		expect(compose).toMatch(/127\.0\.0\.1:3000:3000/);
	});
});

/**
 * What `.gitignore` keeps out of git (secrets and per-machine configuration,
 * the client registry among them) stays out of the build context too: the
 * `Dockerfile` copies `config/`, so a `config/clients.yaml` in the working
 * copy, client secrets included, would be baked into the runtime image.
 * Production is given the registry from outside the image instead.
 */
describe("what .gitignore keeps out of git stays out of the image, and production is given it", () => {
	/**
	 * `.gitignore`'s "Secrets and per-machine configuration" section: each
	 * pattern, with files it matches. A pattern without a `/` matches at any
	 * depth in `.gitignore`, so those carry a nested file too — `.dockerignore`
	 * anchors every pattern at the context root, where `*` stops at a `/`.
	 */
	const PER_DEPLOYMENT: Readonly<Record<string, readonly string[]>> = {
		".env": [".env", "config/.env"],
		".env.*": [".env.local", ".env.production", "config/.env.production"],
		"*.pem": ["jwt-private.pem", "config/jwt-private.pem"],
		"*.key": ["tls.key", "config/tls.key"],
		"config/clients.yaml": ["config/clients.yaml"],
		"config/*.local.conf": ["config/production.local.conf"],
	};

	/**
	 * The committed files beside them, which the image does need. `.env.example`
	 * is what `.gitignore` re-includes, at any depth: the same here.
	 */
	const COMMITTED = [
		".env.example",
		"config/.env.example",
		"config/application.conf",
		"config/development.conf",
		"config/production.conf",
		"config/clients.yaml.example",
	] as const;

	it("checks every pattern of .gitignore's secrets section", () => {
		const lines = read("/.gitignore").split("\n");
		const start = lines.indexOf("# Secrets and per-machine configuration");
		expect(start).not.toBe(-1);
		const section: string[] = [];
		for (const line of lines.slice(start + 1)) {
			if (line.trim() === "") break;
			if (!line.startsWith("#") && !line.startsWith("!")) section.push(line.trim());
		}
		expect(section).toEqual(Object.keys(PER_DEPLOYMENT));
	});

	it.each(Object.entries(PER_DEPLOYMENT))(
		"keeps what %s matches out of the build context",
		(_, files) => {
			const dockerignore = read("/.dockerignore");
			for (const file of files) {
				expect(dockerignoreExcludes(dockerignore, file), `${file} reaches the build context`).toBe(
					true,
				);
			}
		},
	);

	it("lets the committed configuration through", () => {
		const dockerignore = read("/.dockerignore");
		for (const file of COMMITTED) {
			expect(dockerignoreExcludes(dockerignore, file), `${file} is excluded`).toBe(false);
		}
	});

	it("gives the production compose's process the client registry, read-only, from outside the image", () => {
		// A compose secret, like the key pair: mounted read-only under
		// /run/secrets, never part of a layer.
		const name = "client_registry";
		expect(composeAppSecrets("/docker-compose.production.yml")).toContain(name);
		expect(composeSecretFiles("/docker-compose.production.yml").get(name)).toBe(
			"./config/clients.yaml",
		);
		// And the process reads it there, through the real config layers.
		const config = resolveWith(bootableEnv("/docker-compose.production.yml"));
		const client = config.repositories.client as { type: string; yaml?: { path?: string } };
		expect(client.type).toBe("yaml");
		expect(client.yaml?.path).toBe(`/run/secrets/${name}`);
	});
});

/** The secrets a compose file's `app` service mounts. */
function composeAppSecrets(rel: string): string[] {
	const lines = read(rel).split("\n");
	const start = lines.findIndex((line) => /^\s{4}secrets:\s*$/.test(line));
	const names: string[] = [];
	if (start === -1) return names;
	for (const line of lines.slice(start + 1)) {
		if (line.trim() === "" || /^\s*#/.test(line)) continue;
		const match = /^\s{6}-\s*(\S+)\s*$/.exec(line);
		if (!match) break;
		names.push(match[1] as string);
	}
	return names;
}

/** A compose file's top-level `secrets:`, as each name's `file:`. */
function composeSecretFiles(rel: string): Map<string, string> {
	const lines = read(rel).split("\n");
	const start = lines.findIndex((line) => /^secrets:\s*$/.test(line));
	const files = new Map<string, string>();
	if (start === -1) return files;
	let name: string | undefined;
	for (const line of lines.slice(start + 1)) {
		if (line.trim() === "" || /^\s*#/.test(line)) continue;
		if (!/^\s/.test(line)) break;
		const entry = /^\s{2}([A-Za-z0-9_-]+):\s*$/.exec(line);
		if (entry) {
			name = entry[1];
			continue;
		}
		const file = /^\s{4}file:\s*(\S+)\s*$/.exec(line);
		if (file && name !== undefined) files.set(name, file[1] as string);
	}
	return files;
}

describe("the compose files put a store and its lifetime-sibling on the same backend", () => {
	// With express-session on Redis and the user-session stores on memory,
	// express-session survives a restart and the `UserSession` it points at
	// does not: every browser comes back `isAuthenticated` with nothing behind
	// it and /authorize loops until the cookie is deleted by hand.
	// `CORE_DEPLOYMENT_MODE: single` is silent about this on purpose — the replica
	// guard answers "can these stores be shared", not "do these two stores have
	// the same lifetime" — so nothing but this assertion stands behind it.
	for (const file of ["/docker-compose.production.yml", "/docker-compose.yml"]) {
		it(`${file} keeps the user-session stores with the express-session store`, () => {
			const config = resolveWith(bootableEnv(file));
			// Resolved through the real config layers, not read off the file:
			// what matters is the value the process ends up with, whether the
			// compose stated it or `config/application.conf` did.
			expect(config["session-store"]?.storage?.type).toBe("redis");
			expect(config.userSessionStores?.adapter).toBe("redis");
		});
	}

	it("the production compose leaves no store on memory while a sibling is on Redis", () => {
		const config = resolveWith(bootableEnv("/docker-compose.production.yml"));
		// Every store whose records must outlive one process. The federation
		// token store is deliberately absent: this template ships every
		// federation disabled, so nothing writes to it, and turning it on needs
		// an AES key the compose file must not invent.
		expect(config["session-store"]?.storage?.type).toBe("redis");
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

describe("the READMEs' security advice", () => {
	it("does not recommend HTTP_TRUST_PROXY=true in the Japanese README", () => {
		// `trust proxy` is a CIDR/hop policy because `true` means "believe the
		// leftmost forwarded entry from whoever opened the connection". The
		// English README warns against it, and the Japanese one must agree.
		expect(read("/README.ja.md")).not.toMatch(/HTTP_TRUST_PROXY=true/);
	});
});

/**
 * The suite that ships with a scaffolded project has to be green in that
 * project, not only in this workspace. A scaffold installs
 * `@o3co/auth-provider-*` from npm, under `node_modules`, where vitest
 * externalizes them and their own `import "ioredis"` / `import "redis"` never
 * meet the `vi.mock` registry unless inlined; here they are symlinks vitest
 * inlines anyway. And `make test` runs this suite inside the `test` image,
 * where a file the Dockerfile never copied does not exist.
 */
describe("the shipped suite carries what it needs to run outside this repository", () => {
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

	it("ships every setup file vitest.config.mts loads, into the `test` image as well", async () => {
		// vitest refuses to start when a `setupFiles` entry is missing, so a setup
		// file the image never copied fails the whole of `make test`, not one test.
		const configPath = fileURLToPath(new URL("../../vitest.config.mts", import.meta.url));
		const { default: config } = (await import(configPath)) as {
			default: { test?: { setupFiles?: string | readonly string[] } };
		};
		const setupFiles = [config.test?.setupFiles ?? []].flat();
		expect(setupFiles, "the #556 supertest loopback guard is not wired in").not.toHaveLength(0);

		const copied = copiedIntoStage(read("/Dockerfile"), "test");
		const dockerignore = read("/.dockerignore");
		for (const entry of setupFiles) {
			const file = entry.replace(/^\.\//, "");
			expect(existsSync(`${standaloneDir}${file}`), `${file} does not exist`).toBe(true);
			expect(copied.has(file), `${file} is not copied into the test image`).toBe(true);
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
 * Whether `.dockerignore` keeps a file out of the build context, as Docker
 * decides it (moby's patternmatcher): patterns are anchored at the context
 * root, the last matching one wins and a leading `!` re-includes; `*` and `?`
 * stop at a `/`, `**` does not, and `**` followed by `/` also matches no
 * directory at all; a pattern that matches one of the file's parent
 * directories matches the file.
 */
function dockerignoreExcludes(dockerignore: string, file: string): boolean {
	const parents = file.split("/").slice(0, -1);
	const candidates = [file, ...parents.map((_, i) => parents.slice(0, i + 1).join("/"))];
	let excluded = false;
	for (const raw of dockerignore.split("\n")) {
		const line = raw.trim();
		if (line === "" || line.startsWith("#")) continue;
		const negated = line.startsWith("!");
		// Cleaned as Docker cleans a pattern (`filepath.Clean`): a leading `/`
		// or `./` and a trailing `/` say nothing about what it matches.
		const pattern = (negated ? line.slice(1) : line).replace(/^(\.?\/)+/, "").replace(/\/+$/, "");
		let source = "";
		for (let i = 0; i < pattern.length; ) {
			if (pattern.startsWith("**/", i)) {
				source += "(?:.*/)?";
				i += 3;
			} else if (pattern.startsWith("**", i)) {
				source += ".*";
				i += 2;
			} else {
				const char = pattern[i] as string;
				source +=
					char === "*" ? "[^/]*" : char === "?" ? "[^/]" : char.replace(/[.+^${}()|[\]\\]/, "\\$&");
				i += 1;
			}
		}
		const regex = new RegExp(`^${source}$`);
		if (candidates.some((candidate) => regex.test(candidate))) excluded = !negated;
	}
	return excluded;
}

describe("the compose files give the process time to finish a shutdown", () => {
	it.each(["/docker-compose.yml", "/docker-compose.production.yml"])(
		"%s declares a stop_grace_period covering the HTTP drain, the grants cleanup and an exit margin",
		(rel) => {
			// compose's own default is ten seconds — the drain budget alone. With
			// federation grants on, the cleanup that drains a rotated credential's
			// write gets 45 more, and SIGKILL must arrive after that, not during.
			const match = /^\s+stop_grace_period:\s*(\d+)s\s*$/m.exec(read(rel));
			expect(match, `${rel} has no stop_grace_period`).not.toBeNull();
			expect(Number(match?.[1])).toBeGreaterThanOrEqual(60);
		},
	);
});
