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
 * What the template writes while it starts: `src/app.mts` in a process of its
 * own, in development on the memory stores, until it listens and then until
 * it has shut down. Every line on stdout and on stderr is one JSON object from
 * the structured logger — a warning a store gives at boot included.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const templateRoot = fileURLToPath(new URL("../..", import.meta.url));
const tsxCli = createRequire(import.meta.url).resolve("tsx/cli");

const keyPair = generateKeyPairSync("ed25519", {
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

/**
 * Development, with every store the `adapters` section selects in memory.
 * The refresh-token family store has no memory choice in the template; its
 * shared Redis socket points at a port nothing answers, so the run reaches no
 * real server. Nothing is inherited from the test runner's environment but
 * PATH, so its NODE_ENV and LOGGING_LEVEL do not reach the child.
 */
const ENV: Readonly<Record<string, string>> = {
	PATH: process.env.PATH ?? "",
	CONFIG_ENV: "development",
	NODE_ENV: "development",
	LOGGING_LEVEL: "info",
	HTTP_PORT: "0",
	OAUTH_JWT_ISSUER: "http://localhost:3000",
	KEY_STORE_LOCAL_PRIVATE_KEY: keyPair.privateKey,
	KEY_STORE_LOCAL_PUBLIC_KEY: keyPair.publicKey,
	SESSION_STORE_SECRET: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	SESSION_STORE_SECURE: "false",
	SESSION_STORE_NAME: "auth.sid",
	SESSION_STORE_STORAGE_TYPE: "memory",
	ADAPTERS_RATE_LIMITER: "memory",
	ADAPTERS_ATTEMPT_COUNTER: "memory",
	ADAPTERS_USER_SESSION_STORES: "memory",
	ADAPTERS_ACCESS_TOKEN_DENYLIST: "memory",
	ADAPTERS_REPLAY_SEEN_SET: "memory",
	ADAPTERS_CODE_REPOSITORY: "memory",
	ADAPTERS_FEDERATION_TOKEN_STORE: "memory",
	ADAPTERS_MFA_FACTOR_STORE: "memory",
	ADAPTERS_MFA_TRANSACTION_STORE: "memory",
	REDIS_CLIENTS_URL: "redis://127.0.0.1:9",
	REPOSITORIES_USER_HTTP_AUTHENTICATE_URL: "http://127.0.0.1:9/authenticate",
	REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL: "http://127.0.0.1:9/authenticate-by-token",
};

interface Run {
	readonly stdout: string;
	readonly stderr: string;
	readonly listened: boolean;
}

/** Starts the template, stops it once it listens (or gives up), and returns what it wrote. */
function startAndStop(timeoutMs: number): Promise<Run> {
	return new Promise((resolve, reject) => {
		const child: ChildProcess = spawn(process.execPath, [tsxCli, "src/app.mts"], {
			cwd: templateRoot,
			env: ENV,
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		let listened = false;
		const stop = (): void => {
			if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
		};
		const deadline = setTimeout(stop, timeoutMs);
		child.stdout?.setEncoding("utf8").on("data", (chunk: string) => {
			stdout += chunk;
			if (!listened && stdout.includes('"msg":"server_listening"')) {
				listened = true;
				stop();
			}
		});
		child.stderr?.setEncoding("utf8").on("data", (chunk: string) => {
			stderr += chunk;
		});
		child.on("error", (err) => {
			clearTimeout(deadline);
			reject(err);
		});
		child.on("close", () => {
			clearTimeout(deadline);
			resolve({ stdout, stderr, listened });
		});
	});
}

/** Each line of `text` that is not one JSON object. */
function linesThatAreNotJsonObjects(text: string): string[] {
	return text
		.split("\n")
		.filter((line) => line.trim() !== "")
		.filter((line) => {
			try {
				const parsed: unknown = JSON.parse(line);
				return typeof parsed !== "object" || parsed === null || Array.isArray(parsed);
			} catch {
				return true;
			}
		});
}

describe("the template's startup output", () => {
	it("is one JSON object per line on stdout and stderr, in development on the memory stores", async () => {
		const run = await startAndStop(15_000);

		expect(run.listened, `the template did not listen; stderr:\n${run.stderr}`).toBe(true);
		expect(linesThatAreNotJsonObjects(run.stdout)).toEqual([]);
		expect(linesThatAreNotJsonObjects(run.stderr)).toEqual([]);
	}, 30_000);
});
