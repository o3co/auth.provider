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
import {
	type BootstrapMap,
	createApp,
	defaultChallengeCeremonyModule,
	defineModule,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { redisChallengeStoreModule, redisReplaySeenSetModule } from "../src/index.mjs";
import { makeIoredisClients } from "../src/ioredis.mjs";

let container: StartedTestContainer;
let client: Redis;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(120_000)
		.start();
	client = new Redis({
		host: container.getHost(),
		port: container.getMappedPort(6379),
	});
}, 30_000);

afterAll(async () => {
	await client?.quit();
	await container?.stop();
});

describe("A1 wiring — full Redis composition (createApp + redis modules)", () => {
	it("composes per-purpose clients + redis ChallengeStore + redis ReplaySeenSet + default ceremony into a working AppHandle", async () => {
		// Activator: a real downstream consumer (e.g. webauthnModule) would naturally
		// activate `challengeCeremony` and the underlying stores via its own route
		// handler module that requires them. The boot planner only walks `requires`
		// for closure roots (modules with `contributes` or `overrides`), so a marker
		// module that contributes a no-op route AND requires both stores + the
		// ceremony pulls them all into the activation closure.
		const activatorModule = defineModule({
			name: "test-activator",
			requires: ["challengeStore", "replaySeenSet", "challengeCeremony"] as const,
			contributes: {
				routes: [
					{
						mountPath: "/__test_noop__",
						id: "test-noop",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					},
				],
			},
		});

		// `makeValidCoreConfig` supplies the schema-required core sections
		// (CoreConfigSchema is always composed in via composeConfigSchema).
		// The redis modules' own namespaced keys carry per-test isolation
		// prefixes appended after the core baseline.
		const config = {
			...makeValidCoreConfig(),
			redisChallengeStore: { keyPrefix: `chal:wiring-${Date.now()}:` },
			redisReplaySeenSet: { keyPrefix: `replay:wiring-${Date.now()}:` },
		};
		const boot = {
			config: config as never,
			pathResolver: (s: string) => s,
			// Per-purpose client slots — spread all 9 wrappers from makeIoredisClients.
			// challengeStoreClient + replaySeenSetClient are the two slots consumed by
			// redisChallengeStoreModule and redisReplaySeenSetModule respectively.
			...makeIoredisClients(client),
		} satisfies Record<string, unknown> as BootstrapMap;

		const handle = await createApp({
			modules: [
				redisChallengeStoreModule,
				redisReplaySeenSetModule,
				defaultChallengeCeremonyModule,
				activatorModule,
			],
			bootstrapComponents: boot,
		});

		try {
			const ceremony = (handle.components as { challengeCeremony?: { consume: typeof Function } })
				.challengeCeremony as unknown as {
				consume: (s: string, v: string) => Promise<{ outcome: string }>;
			};
			expect(ceremony).toBeDefined();

			const unknown = await ceremony.consume("scope-A", "never-existed");
			expect(unknown.outcome).toBe("unknown");

			const store = (handle.components as { challengeStore?: { issue: typeof Function } })
				.challengeStore as unknown as {
				issue: (s: string, v: string, expMs: number) => Promise<void>;
			};
			await store.issue("scope-A", "live-value", Date.now() + 60_000);
			const consumed = await ceremony.consume("scope-A", "live-value");
			expect(consumed.outcome).toBe("consumed");

			const replayed = await ceremony.consume("scope-A", "live-value");
			expect(replayed.outcome).toBe("replayed");
		} finally {
			await handle.dispose();
		}
	});
});
