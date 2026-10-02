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
 * The `clientRepository` slot at boot: whatever fills it — a provider's
 * value, a host's bootstrap or override value — the slot holds core's
 * client-record boundary over it, so every reader of the slot, a provider's
 * deps and a contribution's alike, reads validated, frozen records and a
 * refused record as the lookup's rejection. A boundary already in the slot
 * is kept as it is, never wrapped twice; a refusal is warned once, through
 * the `logger` component the map holds when it happens.
 */

import { describe, expect, it } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import type { BootstrapMap } from "#/boot/types.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { defineModule, type Module } from "#/modules/manifest/index.mjs";
import type { ClientRepository, PublicClient } from "#/repositories/ClientRepository.mjs";
import { isClientRecordRefused } from "#/repositories/clientRecordRefused.mjs";
import { validatedClientRepository } from "#/repositories/clientRepositoryBoundary.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly clientSlotFixtureReader: { readonly read: true };
	}
}

const CLIENT_ID = "client-1";
const REFUSED_ID = "client-refused";

/** A record the registration schema accepts. */
const validRecord = (clientId: string = CLIENT_ID): PublicClient =>
	({
		clientId,
		tokenEndpointAuthMethod: "client_secret_basic",
		allowedRedirectUris: ["https://rp.example/cb"],
		allowedScopes: ["openid"],
	}) as PublicClient;

/** A record the registration schema refuses: a `javascript:` redirect URI. */
const refusedRecord = (): PublicClient =>
	({
		clientId: REFUSED_ID,
		tokenEndpointAuthMethod: "client_secret_basic",
		allowedRedirectUris: ["javascript:alert(1)"],
		allowedScopes: ["openid"],
	}) as PublicClient;

/** A raw repository: one valid record, one the boundary refuses, nothing else. */
const rawRepository = (): ClientRepository => {
	const records = new Map<string, PublicClient>([
		[CLIENT_ID, validRecord()],
		[REFUSED_ID, refusedRecord()],
	]);
	return {
		findById: async (clientId) => records.get(clientId) ?? null,
		authenticate: async (clientId) => records.get(clientId) ?? null,
	};
};

/** A logger keeping each line's level, fields and message. */
const recordingLogger = () => {
	const lines: { level: string; fields: unknown; message: unknown }[] = [];
	const at = (level: string) => (fields: unknown, message?: unknown) => {
		lines.push({ level, fields, message });
	};
	const logger = {
		trace: () => {},
		debug: () => {},
		info: at("info"),
		warn: at("warn"),
		error: at("error"),
		fatal: () => {},
		child: () => logger,
	} as unknown as Logger;
	const refusals = () => lines.filter((line) => line.message === "client_record_refused");
	return { logger, lines, refusals };
};

const bootWith = (extra: Record<string, unknown> = {}): BootstrapMap =>
	({
		config: makeValidCoreConfig() as never,
		pathResolver: (s: string) => s,
		...extra,
	}) satisfies Record<string, unknown> as BootstrapMap;

const clientProvider = (repository: unknown, name = "test:clients"): Module =>
	defineModule({
		name,
		provides: { clientRepository: () => repository as ClientRepository },
	});

/**
 * Readers of the slot, as the bundled modules are: one through a provider's
 * deps (stage 3), one through a contribution's (stage 4).
 */
function slotReaders() {
	const handed: { provider?: ClientRepository; contribution?: ClientRepository } = {};
	const providerReader = defineModule({
		name: "test:provider-reader",
		requires: ["clientRepository"],
		provides: {
			clientSlotFixtureReader: (deps) => {
				handed.provider = deps.clientRepository;
				return { read: true };
			},
		},
		lifecycle: { clientSlotFixtureReader: { eager: true } },
	});
	const contributionReader = defineModule({
		name: "test:contribution-reader",
		requires: ["clientRepository"],
		contributes: {
			grantMiddleware: [
				(deps) => {
					handed.contribution = deps.clientRepository;
					return null;
				},
			],
		},
	});
	return { modules: [providerReader, contributionReader], handed };
}

/** What `answer` rejects with; fails when it resolves. */
const rejectionOf = async (answer: Promise<unknown>): Promise<unknown> => {
	try {
		await answer;
	} catch (error) {
		return error;
	}
	throw new Error("expected the lookup to reject");
};

/** The reader sees the boundary: a valid record is a frozen copy, a refused one rejects branded. */
async function expectBehindBoundary(repository: ClientRepository | undefined, raw: unknown) {
	expect(repository).toBeDefined();
	const slot = repository as ClientRepository;
	expect(slot).not.toBe(raw);
	// Recognised as a boundary: wrapping it again answers the same object.
	expect(validatedClientRepository(slot)).toBe(slot);
	const found = await slot.findById(CLIENT_ID);
	expect(found).toMatchObject({
		clientId: CLIENT_ID,
		allowedRedirectUris: ["https://rp.example/cb"],
	});
	expect(Object.isFrozen(found)).toBe(true);
	expect(isClientRecordRefused(await rejectionOf(slot.findById(REFUSED_ID)))).toBe(true);
	expect(isClientRecordRefused(await rejectionOf(slot.authenticate(REFUSED_ID, "s")))).toBe(true);
}

describe("the clientRepository slot holds core's client-record boundary", () => {
	it("over a provider's value, for a provider's reader and a contribution's alike", async () => {
		const raw = rawRepository();
		const readers = slotReaders();
		const { logger, refusals } = recordingLogger();

		const handle = await createApp({
			modules: [clientProvider(raw), ...readers.modules],
			bootstrapComponents: bootWith({ logger }),
		});

		await expectBehindBoundary(readers.handed.provider, raw);
		expect(readers.handed.contribution).toBe(readers.handed.provider);
		expect(handle.components.clientRepository).toBe(readers.handed.provider);
		// One warn per refused lookup: findById and authenticate above.
		expect(refusals()).toHaveLength(2);
		expect(refusals()[0]?.fields).toMatchObject({ step: "find", clientId: REFUSED_ID });
	});

	it("over a host's bootstrap value", async () => {
		const raw = rawRepository();
		const readers = slotReaders();
		const { logger, refusals } = recordingLogger();

		await createApp({
			modules: readers.modules,
			bootstrapComponents: bootWith({ logger, clientRepository: raw }),
		});

		await expectBehindBoundary(readers.handed.provider, raw);
		expect(readers.handed.contribution).toBe(readers.handed.provider);
		expect(refusals()).toHaveLength(2);
	});

	it("over a host's override value, which replaces a provider's", async () => {
		const provided = rawRepository();
		const raw = rawRepository();
		const readers = slotReaders();
		const { logger } = recordingLogger();

		await createApp({
			modules: [clientProvider(provided), ...readers.modules],
			bootstrapComponents: bootWith({ logger }),
			overrideComponents: { clientRepository: raw },
		});

		await expectBehindBoundary(readers.handed.provider, raw);
		expect(readers.handed.provider).not.toBe(provided);
		expect(readers.handed.contribution).toBe(readers.handed.provider);
	});

	it("over a callable repository, which carries the port's methods on a function", async () => {
		const callable = Object.assign(function repository() {}, rawRepository());
		const readers = slotReaders();
		const { logger } = recordingLogger();

		await createApp({
			modules: [clientProvider(callable), ...readers.modules],
			bootstrapComponents: bootWith({ logger }),
		});

		await expectBehindBoundary(readers.handed.provider, callable);
	});

	it("keeps a boundary already in the slot as it is: one warn per refusal, on its own logger", async () => {
		const host = recordingLogger();
		const boundary = validatedClientRepository(rawRepository(), { logger: host.logger });
		const readers = slotReaders();
		const composition = recordingLogger();

		await createApp({
			modules: [clientProvider(boundary), ...readers.modules],
			bootstrapComponents: bootWith({ logger: composition.logger }),
		});

		expect(readers.handed.provider).toBe(boundary);
		expect(readers.handed.contribution).toBe(boundary);
		// A reader that wraps the slot again, as oauth's entry points do, gets it back.
		expect(validatedClientRepository(boundary)).toBe(boundary);
		expect(isClientRecordRefused(await rejectionOf(boundary.findById(REFUSED_ID)))).toBe(true);
		expect(host.refusals()).toHaveLength(1);
		expect(composition.refusals()).toHaveLength(0);
	});

	it("passes a refusal from a boundary under a layer through, without a second warn", async () => {
		const { logger, refusals } = recordingLogger();
		const inner = validatedClientRepository(rawRepository(), { logger });
		// A forwarding cache over the boundary that lets rejections through.
		const cache: ClientRepository = {
			findById: (clientId) => inner.findById(clientId),
			authenticate: (clientId, secret) => inner.authenticate(clientId, secret),
		};
		const readers = slotReaders();

		await createApp({
			modules: [clientProvider(cache), ...readers.modules],
			bootstrapComponents: bootWith({ logger }),
		});

		expect(readers.handed.provider).not.toBe(cache);
		expect(
			isClientRecordRefused(
				await rejectionOf((readers.handed.provider as ClientRepository).findById(REFUSED_ID)),
			),
		).toBe(true);
		expect(refusals()).toHaveLength(1);
	});

	it("reads the logger when a refusal happens: a logger provided after the slot is filled says it", async () => {
		const raw = rawRepository();
		const readers = slotReaders();
		const { logger, refusals } = recordingLogger();
		const loggerProvider = defineModule({
			name: "test:logger",
			provides: { logger: () => logger },
			lifecycle: { logger: { eager: true } },
		});

		await createApp({
			modules: [loggerProvider, ...readers.modules],
			bootstrapComponents: bootWith({ clientRepository: raw }),
		});

		await rejectionOf((readers.handed.provider as ClientRepository).findById(REFUSED_ID));
		expect(refusals()).toHaveLength(1);
	});

	it("hands a provider's cleanup its own value, and dispose reaches it through the boundary", async () => {
		const disposed: string[] = [];
		const cleaned: unknown[] = [];
		const withCleanup = rawRepository();
		const cleanupModule = defineModule({
			name: "test:clients-with-cleanup",
			provides: { clientRepository: () => withCleanup },
			lifecycle: {
				clientRepository: {
					cleanup: (value) => {
						cleaned.push(value);
					},
				},
			},
		});
		const disposable = Object.assign(rawRepository(), {
			[Symbol.asyncDispose]: async () => {
				disposed.push("provider");
			},
		});
		const readers = slotReaders();

		const first = await createApp({
			modules: [cleanupModule, ...readers.modules],
			bootstrapComponents: bootWith(),
		});
		await first.dispose();
		expect(cleaned).toEqual([withCleanup]);

		const second = await createApp({
			modules: [clientProvider(disposable), ...slotReaders().modules],
			bootstrapComponents: bootWith(),
		});
		expect(second.components.clientRepository).not.toBe(disposable);
		await second.dispose();
		expect(disposed).toEqual(["provider"]);
	});

	it("boots over a host's value whose every read throws, and never reads it at dispose", async () => {
		const reads: (string | symbol)[] = [];
		const host = new Proxy(
			{},
			{
				get(_target, key) {
					reads.push(key);
					throw new Error("a read boot must not make");
				},
			},
		);

		const handle = await createApp({
			modules: slotReaders().modules,
			bootstrapComponents: bootWith({ clientRepository: host }),
		});
		await handle.dispose();

		// Compared by identity alone: a matcher handed `host` would read it.
		expect(handle.components.clientRepository === host).toBe(false);
		expect(reads).toEqual([]);
	});

	it("never disposes a host's value through the boundary", async () => {
		const disposed: string[] = [];
		const host = Object.assign(rawRepository(), {
			[Symbol.asyncDispose]: async () => {
				disposed.push("host");
			},
		});

		const handle = await createApp({
			modules: slotReaders().modules,
			bootstrapComponents: bootWith({ clientRepository: host }),
		});
		await handle.dispose();

		expect(disposed).toEqual([]);
	});
});
