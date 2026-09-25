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
 * boot/__tests__/factory-failure-message.test.mts — what a boot failure's
 * message carries of the error a factory threw.
 *
 * A boot failure ends the process, and Node prints it — message, fields and
 * cause chain — to stderr, where a deployment's log shipper reads it. The
 * message used to be the factory's error flattened with `String(...)`: a
 * parser's error quotes its input, and js-yaml's quotes the lines around the
 * fault, so a typo in `clients.yaml` printed the neighbouring clients'
 * secrets at boot. The message now names the error by `loggableError`'s
 * rules — its name and message, nothing of a SyntaxError's text, a Redis
 * reply's echoed arguments cut, only the kind of a value that is not an
 * Error — without a log field's length cap, since a refusal's advice is
 * often longer; the error itself is still the BootError's `cause`.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { inspect } from "node:util";
import * as yaml from "js-yaml";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import { BootError, type BootstrapMap } from "#/boot/types.mjs";
import { defineModule, type Module } from "#/modules/manifest/index.mjs";
import { createRepositoryFactories } from "#/repositories/RepositoryFactory.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const bootstrap = {
	config: makeValidCoreConfig() as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

/** Boots `modules` through `createApp` and answers the BootError it must fail with. */
const bootFailure = async (modules: readonly Module[]): Promise<BootError> => {
	const outcome = await createApp({ modules, bootstrapComponents: bootstrap }).then(
		async (handle) => {
			await handle.dispose();
			return undefined;
		},
		(err: unknown) => err,
	);
	expect(outcome).toBeInstanceOf(BootError);
	return outcome as BootError;
};

/** Everything Node's unhandled-rejection printer would show of `err`, and more. */
const printed = (err: unknown): string =>
	inspect(err, { depth: Number.POSITIVE_INFINITY, showHidden: true });

/** A JSON parser's error, which quotes the text it could not parse: V8 quotes it whole. */
const parseErrorQuoting = (marker: string): SyntaxError => {
	try {
		JSON.parse(marker);
	} catch (err) {
		return err as SyntaxError;
	}
	throw new Error("JSON.parse did not throw");
};

describe("a clients file with a YAML error, booted through createApp", () => {
	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), "boot-yaml-"));
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("refuses to boot naming the file and the fault, with no secret in the message or anywhere Node prints", async () => {
		const file = path.join(dir, "clients.yaml");
		fs.writeFileSync(
			file,
			[
				"web:",
				"  clientSecret: web-client-secret-marker",
				"  redirectUris:",
				"   - https://rp.test/cb",
				"  allowedScopes",
				"worker:",
				"  clientSecret: worker-client-secret-marker",
				"",
			].join("\n"),
		);
		// The shipped path: the YAML adapter the standalone template's
		// repositories module builds its client repository with.
		const yamlClientsModule = defineModule({
			name: "test:yaml-clients",
			provides: {
				clientRepository: () =>
					createRepositoryFactories().clientFactory.create({ type: "yaml", path: file }),
			},
			lifecycle: { clientRepository: { eager: true } },
		});

		const err = await bootFailure([yamlClientsModule]);

		expect(err.reason).toBe("provides-factory-failed");
		expect(err.message).toBe(
			`Module "test:yaml-clients" provider factory for "clientRepository" failed: ` +
				`Error: Invalid YAML in ${file} at 5:16: expected ':' after a mapping key`,
		);
		for (const marker of ["web-client-secret-marker", "worker-client-secret-marker"]) {
			expect(err.message).not.toContain(marker);
			expect(printed(err)).not.toContain(marker);
		}
	});
});

describe("a BootError, printed", () => {
	it("prints one built without details, rather than failing to print", () => {
		const err = new BootError({
			message: "a refusal with no details",
			reason: "provides-factory-failed",
			stage: "materializeComponents",
			details: undefined as never,
		});
		expect(printed(err)).toContain("a refusal with no details");
	});
});

describe("a factory's error, in the boot failure's message", () => {
	const providing = (thrown: unknown): Module =>
		defineModule({
			name: "test:failing-provider",
			provides: {
				clientRepository: () => {
					throw thrown;
				},
			},
			lifecycle: { clientRepository: { eager: true } },
		});
	const contributing = (thrown: unknown): Module =>
		defineModule({
			name: "test:failing-route",
			contributes: {
				routes: [
					() => {
						throw thrown;
					},
				],
			},
		});

	it("names a parser's error by its name alone: the message it quoted its input into is left out", async () => {
		for (const [build, prefix] of [
			[
				providing,
				'Module "test:failing-provider" provider factory for "clientRepository" failed: ',
			],
			[contributing, 'Module "test:failing-route" route factory failed: '],
		] as const) {
			const thrown = parseErrorQuoting("json-secret-marker");
			const err = await bootFailure([build(thrown)]);
			expect(err.message).toBe(`${prefix}SyntaxError`);
			// The error itself is still there for a caller that reads it…
			expect(err.cause).toBe(thrown);
			// …and printing the BootError (Node's unhandled-rejection printer,
			// `console.error`) shows the cause's projection, not the cause.
			expect(printed(err)).not.toContain("json-secret-marker");
		}
	});

	it("names a YAML parser's error by its name alone, when a host's own module parses a file", async () => {
		const thrown = (() => {
			try {
				yaml.load("web:\n  clientSecret: host-yaml-secret-marker\n  bad\nnext: 1\n");
			} catch (err) {
				return err;
			}
			throw new Error("yaml.load did not throw");
		})();
		const err = await bootFailure([providing(thrown)]);
		expect(err.message).toBe(
			'Module "test:failing-provider" provider factory for "clientRepository" failed: YAMLException',
		);
		expect(printed(err)).not.toContain("host-yaml-secret-marker");
	});

	it("names only the kind of a thrown value that is not an Error", async () => {
		const err = await bootFailure([providing("string-secret-marker")]);
		expect(err.message).toBe(
			'Module "test:failing-provider" provider factory for "clientRepository" failed: a thrown string',
		);
		expect(err.cause).toBe("string-secret-marker");
		expect(printed(err)).not.toContain("string-secret-marker");
	});

	it("cuts the arguments a Redis reply echoes, as a log line does", async () => {
		const err = await bootFailure([
			providing(
				Object.assign(
					new Error(
						"ERR Error running script, with args beginning with: 'fed-token:u1' 'redis-args-secret-marker'",
					),
					{ name: "ReplyError" },
				),
			),
		]);
		expect(err.message).toBe(
			'Module "test:failing-provider" provider factory for "clientRepository" failed: ReplyError: ERR Error running script',
		);
		expect(printed(err)).not.toContain("redis-args-secret-marker");
	});

	it("prints a cleanup's failure by its projection too", async () => {
		// A component already built is cleaned up when a later factory fails;
		// the cleanup's own error — a store's, carrying the command it refused
		// — rides on the BootError's `details.cleanupErrors`.
		const closing = defineModule({
			name: "test:closing-store",
			provides: { codeRepository: () => ({}) as never },
			lifecycle: {
				codeRepository: {
					eager: true,
					cleanup: () => {
						throw Object.assign(new Error("QUIT refused"), {
							command: { name: "quit", args: ["cleanup-args-secret-marker"] },
						});
					},
				},
			},
		});
		const failing = defineModule({
			name: "test:failing-after",
			requires: ["codeRepository"] as const,
			provides: {
				clientRepository: () => {
					throw new Error("boom");
				},
			},
			lifecycle: { clientRepository: { eager: true } },
		});
		const err = await bootFailure([closing, failing]);
		expect(err.details).toMatchObject({
			reason: "provides-factory-failed",
			cleanupErrors: [{ module: "test:closing-store", componentKey: "codeRepository" }],
		});
		expect(printed(err)).toContain("QUIT refused");
		expect(printed(err)).not.toContain("cleanup-args-secret-marker");
	});

	it("keeps an Error's whole message: a refusal's advice, at its end, is what an operator acts on", async () => {
		const advice = `oauth.example.limit must be positive${" and so on".repeat(40)} — set it to 10`;
		const err = await bootFailure([providing(new RangeError(advice))]);
		expect(err.message).toBe(
			`Module "test:failing-provider" provider factory for "clientRepository" failed: RangeError: ${advice}`,
		);
	});
});
