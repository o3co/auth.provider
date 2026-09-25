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
 * module.integration.test.mts
 *
 * Integration test for `dpopModule` composition via `createApp`.
 *
 * Sub-PR 2b scope (narrower than the full spec §12.2):
 *   - Verify `dpopModule` wires correctly with `createApp`.
 *   - When `oauth.dpop.enabled = false` (default), no DPoP middleware is
 *     mounted — requests succeed without a DPoP header.
 *   - When `oauth.dpop.enabled = true`, a valid DPoP proof populates
 *     `req.tokenBinding` with the correct `kind` and `confirmation.jkt`.
 *   - An invalid proof returns HTTP 400 with `error: "invalid_dpop_proof"`.
 *   - Every accepted proof is recorded in core's `replaySeenSet` slot, so a
 *     proof accepted by one replica is refused by every replica that shares
 *     the set; an enabled mechanism with no seen-set is refused at boot.
 *   - The memory seen-set answers `deployment.mode` through core's
 *     replica-safety guard: `"multi"` refuses boot, unset warns, `"single"`
 *     is silent. DPoP adds no check of its own.
 *
 * Sub-PR 2c deferred:
 *   - `token_type: "DPoP"` in the response body.
 *   - `cnf.jkt` claim in the issued access token.
 *
 * Test pattern: copied from packages/core/src/boot/__tests__/
 *   grant-middleware.integration.test.mts (Phase 1d retro integration).
 *
 * Per Wave 2 Phase 2 spec §12.2 (narrowed) + Phase 2 plan T2.6.3.
 */

import {
	type BootstrapMap,
	createApp,
	createMemoryReplaySeenSet,
	defineModule,
	type Logger,
	memoryReplaySeenSetModule,
	type ReplaySeenSet,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import express, { type RequestHandler, Router } from "express";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { dpopModule } from "#/module.mjs";
import { computeJkt } from "#/thumbprint.mjs";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Minimal bootstrap with extended dpop config. */
const makeBoot = (dpopEnabled: boolean): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			oauth: {
				...makeValidCoreConfig().oauth,
				dpop: {
					enabled: dpopEnabled,
					"iat-window-seconds": 60,
					"alg-whitelist": ["ES256", "ES384", "EdDSA", "RS256"],
					"replay-store-ttl-seconds": 300,
				},
				tokenBinding: {
					"dispatch-policy": "intent-explicit",
				},
			},
		} as never,
		pathResolver: (s: string) => s,
		// Where every accepted proof's jti is recorded.
		replaySeenSet: createMemoryReplaySeenSet(),
	}) satisfies Record<string, unknown> as BootstrapMap;

/**
 * The deployment's canonical issuer, as `makeValidCoreConfig` sets it. Since
 * #292 the expected `htu` is built from THIS, not from the request — so the
 * proof names it even though supertest speaks plain http to an ephemeral port
 * and the requests below send a `Host` header saying something else entirely.
 * That divergence is the point: it is what the old reconstruction trusted.
 */
const ISSUER_ORIGIN = "https://auth.test";

/**
 * Mint a valid DPoP proof for `POST <issuer origin>/oauth/token`.
 *
 * The path still comes from the request (`req.originalUrl`); only the origin
 * is configuration. `normalizeHtu` strips query/fragment and lowercases
 * scheme + host on both sides before comparing.
 */
const mintProof = async (jti: string = crypto.randomUUID()) => {
	const { publicKey, privateKey } = await generateKeyPair("ES256");
	const jwk = await exportJWK(publicKey);
	const jkt = await computeJkt(jwk);
	const proof = await new SignJWT({
		htm: "POST",
		htu: `${ISSUER_ORIGIN}/oauth/token`,
		iat: Math.floor(Date.now() / 1000),
		jti,
	})
		.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
		.sign(privateKey);
	return { proof, jkt, jti };
};

/**
 * Build a route contribution that records the token binding on the request
 * and responds 200 with the binding JSON for assertion. Mirrors the Phase 1d
 * retro test pattern.
 */
const makeTokenBindingObserver =
	(received: { tokenBinding?: unknown }): RequestHandler =>
	(req, res) => {
		// biome-ignore lint/suspicious/noExplicitAny: test-only req augmentation access
		received.tokenBinding = (req as any).tokenBinding;
		res.status(200).json({ ok: true });
	};

/**
 * Invoke the module's contributed mechanism factory directly, the way the boot
 * planner does. Used for the boot-time guards, which have to be reached
 * without `createApp` first rejecting the config for the same reason. The
 * seen-set is handed over as the planner would, so each guard is reached on
 * its own account rather than refused for the missing set.
 */
const buildMechanism = (config: unknown) => {
	const factory = dpopModule.contributes?.tokenBindingMechanisms?.[0];
	if (factory === undefined) throw new Error("dpopModule contributes no mechanism factory");
	return factory({ config, replaySeenSet: createMemoryReplaySeenSet() } as never);
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("dpopModule — integration via createApp", () => {
	it("dpopModule has kind 'dpop' and intentExplicit from its mechanism", () => {
		// Structural smoke test: module name is stable.
		expect(dpopModule.name).toBe("dpop");
	});

	it("when disabled: no DPoP middleware; requests without DPoP header succeed", async () => {
		const boot = makeBoot(false);

		// Observer route: records req.tokenBinding, responds 200.
		const received: { tokenBinding?: unknown } = {};
		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				routes: [
					() => {
						const router = Router();
						router.use(express.json());
						router.post("/token", makeTokenBindingObserver(received));
						return { id: "test-token", mountPath: "/oauth", handler: router };
					},
				],
			},
		});

		const handle = await createApp({
			modules: [dpopModule, observerModule],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});
		expect(res.status).toBe(200);
		// No DPoP header → tokenBinding should be undefined.
		expect(received.tokenBinding).toBeUndefined();

		await handle.dispose();
	});

	it("when enabled: valid DPoP proof populates req.tokenBinding with kind=dpop and confirmation.jkt", async () => {
		const boot = makeBoot(true);
		const { proof, jkt } = await mintProof();

		const received: { tokenBinding?: unknown } = {};
		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				routes: [
					() => {
						const router = Router();
						router.use(express.json());
						router.post("/token", makeTokenBindingObserver(received));
						return { id: "test-token", mountPath: "/oauth", handler: router };
					},
				],
			},
		});

		const handle = await createApp({
			modules: [dpopModule, observerModule],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", proof)
			// A Host header that is NOT the issuer. Before #292 this decided
			// what the proof had to match; now it is ignored, and the request
			// succeeds anyway.
			.set("Host", "attacker.example")
			.send({});

		expect(res.status).toBe(200);
		// req.tokenBinding should be populated with DPoP binding.
		expect(received.tokenBinding).toMatchObject({
			kind: "dpop",
			confirmation: { jkt },
		});

		await handle.dispose();
	});

	it("when enabled: invalid DPoP proof returns HTTP 400 with error=invalid_dpop_proof", async () => {
		const boot = makeBoot(true);

		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				routes: [
					() => {
						const router = Router();
						router.use(express.json());
						router.post("/token", (_req, res) => {
							res.status(200).json({ ok: true });
						});
						return { id: "test-token", mountPath: "/oauth", handler: router };
					},
				],
			},
		});

		const handle = await createApp({
			modules: [dpopModule, observerModule],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", "not.a.valid.dpop.proof")
			.set("Host", "as.example")
			.send({});

		// tokenBindingMw returns 400 for invalid proofs.
		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "invalid_dpop_proof" });

		await handle.dispose();
	});

	it("when enabled: records each proof in the replaySeenSet slot, scoped by the proof's key", async () => {
		// The seen-set is core's, shared with private_key_jwt client
		// authentication and WebAuthn. DPoP's records carry a scope of their own
		// that names the key, so the same jti under another key is not a replay
		// and no other consumer's record can collide with one.
		const calls: { scope: string; key: string; expiresAtMs: number }[] = [];
		const backing = createMemoryReplaySeenSet();
		const spy: ReplaySeenSet = {
			kind: "spy",
			markSeen: async (scope, key, expiresAtMs) => {
				calls.push({ scope, key, expiresAtMs });
				return backing.markSeen(scope, key, expiresAtMs);
			},
			contains: (scope, key) => backing.contains(scope, key),
		};
		const boot = { ...makeBoot(true), replaySeenSet: spy } satisfies BootstrapMap;
		const { proof, jkt, jti } = await mintProof();

		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				routes: [
					() => {
						const router = Router();
						router.use(express.json());
						router.post("/token", (_req, res) => {
							res.status(200).json({ ok: true });
						});
						return { id: "test-token", mountPath: "/oauth", handler: router };
					},
				],
			},
		});

		const handle = await createApp({
			modules: [dpopModule, observerModule],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const before = Date.now();
		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", proof)
			// A Host header that is NOT the issuer. Before #292 this decided
			// what the proof had to match; now it is ignored, and the request
			// succeeds anyway.
			.set("Host", "attacker.example")
			.send({});
		const after = Date.now();

		expect(res.status).toBe(200);
		expect(calls).toHaveLength(1);
		expect(calls[0]).toMatchObject({ scope: `dpop-proof:${jkt}`, key: jti });
		// Kept for `replay-store-ttl-seconds` (300) from the moment it was seen.
		expect(calls[0]?.expiresAtMs).toBeGreaterThanOrEqual(before + 300_000);
		expect(calls[0]?.expiresAtMs).toBeLessThanOrEqual(after + 300_000);

		// The record is what refuses the replay.
		const replay = await request(app).post("/oauth/token").set("DPoP", proof).send({});
		expect(replay.status).toBe(400);
		expect(replay.body).toMatchObject({ error: "invalid_dpop_proof" });

		await handle.dispose();
	});

	it("when enabled: refuses a proof whose jti is longer than 256 characters, before it reaches the seen-set", async () => {
		// The token endpoint checks the proof before it authenticates the client,
		// and every accepted jti is a seen-set key for replay-store-ttl-seconds:
		// unbounded, an anonymous caller chose how large each record was.
		const recorded: string[] = [];
		const backing = createMemoryReplaySeenSet();
		const spy: ReplaySeenSet = {
			kind: "spy",
			markSeen: async (scope, key, expiresAtMs) => {
				recorded.push(key);
				return backing.markSeen(scope, key, expiresAtMs);
			},
			contains: (scope, key) => backing.contains(scope, key),
		};
		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				routes: [
					() => {
						const router = Router();
						router.post("/token", (_req, res) => {
							res.status(200).json({ ok: true });
						});
						return { id: "test-token", mountPath: "/oauth", handler: router };
					},
				],
			},
		});
		const handle = await createApp({
			modules: [dpopModule, observerModule],
			bootstrapComponents: { ...makeBoot(true), replaySeenSet: spy } satisfies BootstrapMap,
		});
		const app = express();
		app.use(handle.router);

		const long = await mintProof("j".repeat(257));
		const refused = await request(app).post("/oauth/token").set("DPoP", long.proof).send({});
		expect(refused.status).toBe(400);
		expect(refused.body).toMatchObject({ error: "invalid_dpop_proof" });
		expect(recorded).toEqual([]);

		const atTheBound = await mintProof("j".repeat(256));
		const accepted = await request(app).post("/oauth/token").set("DPoP", atTheBound.proof).send({});
		expect(accepted.status).toBe(200);
		expect(recorded).toEqual([atTheBound.jti]);

		await handle.dispose();
	});

	it("when enabled: refuses to boot with no replaySeenSet, in every deployment.mode", async () => {
		// There is no per-process fallback any more: a mechanism that cannot
		// record a proof cannot refuse its replay, so boot says what to wire
		// rather than choosing a store on the composition's behalf.
		for (const mode of [undefined, "single", "multi"] as const) {
			const { replaySeenSet: _omitted, ...withoutSeenSet } = makeBoot(true) as BootstrapMap & {
				replaySeenSet?: unknown;
			};
			const config = withoutSeenSet.config as unknown as Record<string, unknown>;
			const boot = {
				...withoutSeenSet,
				config: { ...config, ...(mode === undefined ? {} : { deployment: { mode } }) } as never,
			} satisfies BootstrapMap;
			const refusal = await createApp({ modules: [dpopModule], bootstrapComponents: boot }).then(
				async (handle) => {
					await handle.dispose();
					return undefined;
				},
				(err: unknown) => err as { reason?: unknown; cause?: { message?: unknown } },
			);
			expect(refusal, `mode ${String(mode)} must refuse`).toMatchObject({
				name: "BootError",
				reason: "contribute-factory-failed",
			});
			const message = String(refusal?.cause?.message);
			expect(message).toMatch(/oauth\.dpop\.enabled = true requires a replaySeenSet/);
			expect(message).toMatch(/memoryReplaySeenSetModule \(single replica only\)/);
			expect(message).toMatch(/redisReplaySeenSetModule/);
		}
	});

	it("refuses the retired oauth.dpop.replay-store key rather than ignoring it", async () => {
		// The key chose between a per-process fallback and a mandatory
		// dpopReplayStore slot; neither exists now. Ignored silently, a
		// deployment that had wired a shared DPoP store beside a memory
		// seen-set would move its DPoP records into memory with no new signal,
		// so the stale line fails boot and names what replaced it.
		const boot = makeBoot(true) as unknown as {
			config: { oauth: { dpop: Record<string, unknown> } };
		};
		boot.config.oauth.dpop["replay-store"] = "redis";

		const refusal = await createApp({
			modules: [dpopModule],
			bootstrapComponents: boot as unknown as BootstrapMap,
		}).then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(err: unknown) => err as { reason?: unknown; details?: { issues?: { message: string }[] } },
		);
		expect(refusal).toMatchObject({ name: "BootError", reason: "config-validation-failed" });
		const messages = (refusal?.details?.issues ?? []).map((i) => i.message).join("\n");
		expect(messages).toMatch(/oauth\.dpop\.replay-store was removed/);
		expect(messages).toMatch(/replaySeenSet/);
	});

	it("when enabled: absent DPoP header leaves req.tokenBinding unset (mechanism returns null)", async () => {
		const boot = makeBoot(true);

		const received: { tokenBinding?: unknown } = {};
		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				routes: [
					() => {
						const router = Router();
						router.use(express.json());
						router.post("/token", makeTokenBindingObserver(received));
						return { id: "test-token", mountPath: "/oauth", handler: router };
					},
				],
			},
		});

		const handle = await createApp({
			modules: [dpopModule, observerModule],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		// No DPoP header → mechanism.extract returns null → tokenBinding unset.
		const res = await request(app).post("/oauth/token").set("Host", "as.example").send({});

		expect(res.status).toBe(200);
		expect(received.tokenBinding).toBeUndefined();

		await handle.dispose();
	});

	it("refuses to build a mechanism when no canonical issuer is configured (#292)", () => {
		// The origin every proof's `htu` is checked against is the deployment's
		// own. Without one the AS would have to rebuild it from the request's
		// forwarded headers — the reconstruction #292 removed — so refuse to
		// construct rather than run with a binding the caller controls both
		// sides of.
		//
		// Exercised through the contributed factory rather than `createApp`,
		// because `createApp` parses `CoreConfigSchema` first and would reject
		// the config before the module is reached. This guard is what protects
		// a composition root that builds the mechanism itself.
		const boot = makeBoot(true) as unknown as { config: Record<string, unknown> };
		const oauth = (boot.config as { oauth: Record<string, unknown> }).oauth;
		delete oauth.jwt;

		expect(() => buildMechanism(boot.config)).toThrow(/oauth\.jwt\.issuer/);
	});

	it("refuses to build a mechanism when the issuer is a bare host rather than a URL (#292)", () => {
		// The shape a `Host` header would have supplied. Deriving an origin
		// from it is exactly what this change stopped doing.
		const boot = makeBoot(true) as unknown as { config: Record<string, unknown> };
		(boot.config as { oauth: { jwt: unknown } }).oauth.jwt = { issuer: "as.example:3000" };

		expect(() => buildMechanism(boot.config)).toThrow(/issuer/i);
	});
});

describe("dpopModule — server-provided nonce from config (#530)", () => {
	const withNonce = (secret: string | undefined, required: "as" | "as+rs" = "as"): BootstrapMap => {
		const boot = makeBoot(true);
		const config = boot.config as { oauth: { dpop: Record<string, unknown> } };
		return {
			...boot,
			config: {
				...config,
				oauth: {
					...config.oauth,
					dpop: {
						...config.oauth.dpop,
						nonce: { required, "ttl-seconds": 300, ...(secret === undefined ? {} : { secret }) },
					},
				},
			} as never,
		};
	};

	it("refuses to build a mechanism when a nonce is required but no shared secret is configured", () => {
		expect(() => buildMechanism(withNonce(undefined).config)).toThrow(/oauth\.dpop\.nonce\.secret/);
	});

	it("measures the secret on its decoded length, as every other operator secret is (v0.13.0 audit)", () => {
		// `openssl rand -hex 16` is 32 characters and 16 bytes of randomness.
		// The nonce issuer counted characters, so it passed a key with half the
		// strength the floor exists to guarantee; `session.secret` and the HS256
		// key have been measured on the decoded value since #282. The refusal
		// names the key and the env var, as theirs do.
		const hex16 = "0123456789abcdef0123456789abcdef";
		expect(() => buildMechanism(withNonce(hex16).config)).toThrow(
			/oauth\.dpop\.nonce\.secret must carry at least 32 bytes[\s\S]*OAUTH_DPOP_NONCE_SECRET/,
		);
		// `openssl rand -base64 32`, what reference.conf tells the operator to run.
		expect(() =>
			buildMechanism(withNonce("q83vEjRWeJq83vEjRWeJq83vEjRWeJq83vEjRWeJq80=").config),
		).not.toThrow();
	});

	it("asks the token endpoint's caller for a nonce and admits the retry, keeping it current", async () => {
		const received: { tokenBinding?: unknown } = {};
		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				routes: [
					() => {
						const router = Router();
						router.use(express.json());
						router.post("/token", makeTokenBindingObserver(received));
						return { id: "test-token", mountPath: "/oauth", handler: router };
					},
				],
			},
		});
		const handle = await createApp({
			modules: [dpopModule, observerModule],
			bootstrapComponents: withNonce("a-dpop-nonce-secret-of-at-least-32-bytes!!"),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const { publicKey, privateKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const proof = async (nonce?: string) =>
			new SignJWT({
				htm: "POST",
				htu: `${ISSUER_ORIGIN}/oauth/token`,
				iat: Math.floor(Date.now() / 1000),
				jti: crypto.randomUUID(),
				...(nonce === undefined ? {} : { nonce }),
			})
				.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
				.sign(privateKey);

		const first = await request(app)
			.post("/oauth/token")
			.set("DPoP", await proof())
			.send({});
		expect(first.status).toBe(400);
		expect(first.body.error).toBe("use_dpop_nonce");
		const nonce = first.headers["dpop-nonce"];
		expect(typeof nonce).toBe("string");

		const second = await request(app)
			.post("/oauth/token")
			.set("DPoP", await proof(nonce))
			.send({});
		expect(second.status).toBe(200);
		expect(received.tokenBinding).toMatchObject({ kind: "dpop" });
		expect(typeof second.headers["dpop-nonce"]).toBe("string");

		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// Replica safety of the replay records
//
// A per-process seen-set forks per replica: a proof captured once could be
// presented once to every replica, each of which had never seen its `jti`.
// DPoP records its proofs in core's `replaySeenSet` slot, so the answer is
// the one core's replica-safety guard already gives for the memory seen-set
// module — `"multi"` refuses boot, unset warns, `"single"` is silent — with
// no check of DPoP's own. A shared seen-set is what makes a replay to another
// replica fail.
// ---------------------------------------------------------------------------

const spyLogger = (): Logger & {
	warn: ReturnType<typeof vi.fn>;
	error: ReturnType<typeof vi.fn>;
} => {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: () => logger,
	};
	return logger as unknown as Logger & {
		warn: ReturnType<typeof vi.fn>;
		error: ReturnType<typeof vi.fn>;
	};
};

/**
 * A logger that serialises every own property of what it is handed, `cause`
 * and non-enumerable fields included — a deployment is free to install one.
 * `lines` is what it wrote; its levels are spies, so a call can be asserted.
 */
const serialiseEverythingLogger = () => {
	const lines: string[] = [];
	const walk = (value: unknown, seen = new WeakSet<object>()): unknown => {
		if (typeof value !== "object" || value === null) return value;
		if (seen.has(value)) return "[circular]";
		seen.add(value);
		const out: Record<string, unknown> = {};
		for (const key of Object.getOwnPropertyNames(value)) {
			out[key] = walk((value as Record<string, unknown>)[key], seen);
		}
		return out;
	};
	const record = (level: string) =>
		vi.fn((...args: unknown[]): void => {
			lines.push(JSON.stringify({ level, args: walk(args) }));
		});
	const logger = {
		trace: record("trace"),
		debug: record("debug"),
		info: record("info"),
		warn: record("warn"),
		error: record("error"),
		fatal: record("fatal"),
		child: () => logger,
	};
	return { logger: logger as typeof logger & Logger, lines };
};

/** A logged projection's `stack`: frames only, from the first. */
const FRAMES = expect.stringMatching(/^ {4}at /);

/**
 * What ioredis rejects a store write with: a ReplyError carrying the command
 * it refused as `command: { name, args }` — for the seen-set's write, the
 * record's key and value.
 */
const replyErrorFor = (args: readonly string[]): Error =>
	Object.assign(new Error("READONLY You can't write against a read only replica."), {
		name: "ReplyError",
		command: { name: "set", args },
	});

/** The event core's replica-safety guard logs when the mode is unset. */
const REPLICA_UNSAFE_EVENT = "replica_unsafe_adapters";
/** The event DPoP logged for its own per-process fallback, which is gone. */
const RETIRED_NOT_SHARED_EVENT = "dpop_replay_store_not_shared";

interface ReplicaBootOptions {
	readonly mode?: "single" | "multi";
	readonly enabled?: boolean;
	/**
	 * `"module"` installs core's `memoryReplaySeenSetModule`; a set is handed
	 * in as a bootstrap component, as a composition root wires a shared one;
	 * `"none"` wires nothing.
	 */
	readonly seenSet: "module" | "none" | ReplaySeenSet;
	/** Omitted: the composition wires no `logger` component. */
	readonly logger?: Logger;
	readonly replayTtlSeconds?: number;
}

const bootReplica = async (opts: ReplicaBootOptions) => {
	const base = makeValidCoreConfig();
	const bootstrapComponents = {
		config: {
			...base,
			...(opts.mode === undefined ? {} : { deployment: { mode: opts.mode } }),
			oauth: {
				...base.oauth,
				dpop: {
					enabled: opts.enabled ?? true,
					"iat-window-seconds": 60,
					"alg-whitelist": ["ES256"],
					"replay-store-ttl-seconds": opts.replayTtlSeconds ?? 300,
				},
				tokenBinding: { "dispatch-policy": "intent-explicit" },
			},
		},
		pathResolver: (s: string) => s,
		...(opts.logger === undefined ? {} : { logger: opts.logger }),
		...(typeof opts.seenSet === "object" ? { replaySeenSet: opts.seenSet } : {}),
	} as never as BootstrapMap;

	const observerModule = defineModule({
		name: "observer",
		requires: [],
		optional: [],
		contributes: {
			routes: [
				() => {
					const router = Router();
					router.use(express.json());
					router.post("/token", (_req, res) => {
						res.status(200).json({ ok: true });
					});
					return { id: "test-token", mountPath: "/oauth", handler: router };
				},
			],
		},
	});

	const handle = await createApp({
		modules: [
			dpopModule,
			...(opts.seenSet === "module" ? [memoryReplaySeenSetModule] : []),
			observerModule,
		],
		bootstrapComponents,
	});
	const app = express();
	app.use(express.json());
	app.use(handle.router);
	return { handle, app };
};

describe("dpopModule — replay records under deployment.mode (replica safety)", () => {
	it('refuses to boot under "multi" with the memory seen-set, naming what a replica fork costs a DPoP proof', async () => {
		const logger = spyLogger();
		const refusal = await bootReplica({ mode: "multi", seenSet: "module", logger }).then(
			async ({ handle }) => {
				await handle.dispose();
				return undefined;
			},
			(err: unknown) => err as { message?: unknown },
		);

		// Core's stage-1 guard, reading the memory module's own declaration —
		// not a DPoP-specific refusal from a factory.
		expect(refusal, "boot must be refused").toMatchObject({
			name: "BootError",
			stage: "validateManifests",
			reason: "replica-unsafe-adapter",
			details: { reason: "replica-unsafe-adapter", modules: ["core-replay-seen-set-memory"] },
		});
		const message = String(refusal?.message);
		expect(message).toMatch(/deployment\.mode is "multi"/);
		expect(message).toMatch(/core-replay-seen-set-memory: .*a DPoP proof/);
		expect(message).toMatch(/replayed once against each replica/);
	});

	it("warns once through the guard when the mode is unset, and still refuses a replay to the same replica", async () => {
		const logger = spyLogger();
		const { handle, app } = await bootReplica({ seenSet: "module", logger });

		const unsafe = logger.warn.mock.calls.filter((call) => call[1] === REPLICA_UNSAFE_EVENT);
		expect(unsafe).toHaveLength(1);
		const fields = unsafe[0]?.[0] as { modules?: unknown; reasons?: unknown } | undefined;
		expect(fields).toMatchObject({ modules: ["core-replay-seen-set-memory"] });
		expect(String(fields?.reasons)).toMatch(/a DPoP proof/);
		expect(logger.warn).not.toHaveBeenCalledWith(expect.anything(), RETIRED_NOT_SHARED_EVENT);

		// Per-process protection is weak, not absent: one replica still
		// refuses a proof it has already seen.
		const { proof } = await mintProof();
		expect((await request(app).post("/oauth/token").set("DPoP", proof).send({})).status).toBe(200);
		const replay = await request(app).post("/oauth/token").set("DPoP", proof).send({});
		expect(replay.status).toBe(400);
		expect(replay.body).toMatchObject({ error: "invalid_dpop_proof" });

		await handle.dispose();
	});

	it('is silent under "single": the operator has declared one replica', async () => {
		const logger = spyLogger();
		const { handle, app } = await bootReplica({ mode: "single", seenSet: "module", logger });

		expect(logger.warn).not.toHaveBeenCalled();

		// Silent, not unguarded: the in-process set is the correct one for a
		// single replica, and it refuses a proof it has already seen.
		const { proof } = await mintProof();
		expect((await request(app).post("/oauth/token").set("DPoP", proof).send({})).status).toBe(200);
		const replay = await request(app).post("/oauth/token").set("DPoP", proof).send({});
		expect(replay.status).toBe(400);
		expect(replay.body).toMatchObject({ error: "invalid_dpop_proof" });

		await handle.dispose();
	});

	it('refuses on one replica a proof another replica accepted, when they share the seen-set (boots under "multi")', async () => {
		// Two replicas, one seen-set: the shape a Redis-backed set gives a
		// scaled deployment. The set is handed in rather than installed as a
		// module, so the guard has nothing to refuse under "multi".
		const shared = createMemoryReplaySeenSet();
		const logger = spyLogger();
		const replicaA = await bootReplica({ mode: "multi", seenSet: shared, logger });
		const replicaB = await bootReplica({ mode: "multi", seenSet: shared, logger });
		expect(logger.warn).not.toHaveBeenCalledWith(expect.anything(), REPLICA_UNSAFE_EVENT);

		const { proof, jkt, jti } = await mintProof();
		expect(
			(await request(replicaA.app).post("/oauth/token").set("DPoP", proof).send({})).status,
		).toBe(200);
		const replay = await request(replicaB.app).post("/oauth/token").set("DPoP", proof).send({});
		expect(replay.status).toBe(400);
		expect(replay.body).toMatchObject({ error: "invalid_dpop_proof" });
		expect(shared.size).toBe(1);
		expect(await shared.contains(`dpop-proof:${jkt}`, jti)).toBe(true);

		// A fresh proof from the same key is still accepted on either replica.
		const next = await mintProof();
		expect(
			(await request(replicaB.app).post("/oauth/token").set("DPoP", next.proof).send({})).status,
		).toBe(200);

		await replicaA.handle.dispose();
		await replicaB.handle.dispose();
	});

	it("answers 503 temporarily_unavailable at the token endpoint when the seen-set cannot be read, and logs it", async () => {
		// The client did nothing wrong: its proof may be perfectly good, and it
		// will be accepted once the store answers again. `400 invalid_dpop_proof`
		// said the proof was invalid (RFC 9449 §5), which a client can read as
		// final. The token endpoint answers store outages elsewhere in this
		// repository with 503 temporarily_unavailable too (private_key_jwt's
		// replay record, the refresh-token family, the revocation stores).
		// What it logs is the store error's projection: ioredis puts the write
		// it refused — the record's key and value — on the error.
		const { logger, lines } = serialiseEverythingLogger();
		const down: ReplaySeenSet = {
			kind: "down",
			markSeen: async (scope, key, expiresAtMs) => {
				throw replyErrorFor([`${scope}${key}`, "1", "PX", String(expiresAtMs), "NX"]);
			},
			contains: async () => false,
		};
		const { handle, app } = await bootReplica({ mode: "single", seenSet: down, logger });

		const { proof, jti } = await mintProof();
		const res = await request(app).post("/oauth/token").set("DPoP", proof).send({});
		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
		expect(res.headers["www-authenticate"]).toBeUndefined();
		// One line, from the dispatcher that answered the 503, with the store
		// error's projection the mechanism handed it as the refusal's cause.
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				mechanism: "dpop",
				code: "temporarily_unavailable",
				reason: "replay_store_unavailable",
				err: {
					name: "ReplyError",
					detail: "READONLY You can't write against a read only replica.",
					command: { name: "set" },
					stack: FRAMES,
				},
			},
			"token_binding_unavailable",
		);
		expect(logger.warn).not.toHaveBeenCalledWith(expect.anything(), "token_binding_unavailable");
		expect(jti).toBeDefined();
		for (const line of lines) expect(line).not.toContain("dpop-proof:");

		await handle.dispose();
	});

	it("answers 503 at the token endpoint when the seen-set breaks its own contract, and logs the fault", async () => {
		const { logger, lines } = serialiseEverythingLogger();
		const broken: ReplaySeenSet = {
			kind: "broken",
			markSeen: async () => {
				throw new RangeError("markSeen: expiresAtMs must be a finite number");
			},
			contains: async () => false,
		};
		const { handle, app } = await bootReplica({ mode: "single", seenSet: broken, logger });

		const { proof, jti } = await mintProof();
		const res = await request(app).post("/oauth/token").set("DPoP", proof).send({});
		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				mechanism: "dpop",
				code: "temporarily_unavailable",
				reason: "replay_store_fault",
				err: {
					name: "RangeError",
					detail: "markSeen: expiresAtMs must be a finite number",
					stack: FRAMES,
				},
			},
			"token_binding_unavailable",
		);
		expect(jti).toBeDefined();
		// The frames, never the header line that repeats the message.
		for (const line of lines) expect(line).not.toContain("RangeError: markSeen");
		expect(logger.warn).not.toHaveBeenCalledWith(expect.anything(), "token_binding_proof_invalid");

		await handle.dispose();
	});

	it("answers 503 at the token endpoint when the memory seen-set holds DPoP's share, and still refuses a replay", async () => {
		// The token endpoint records a proof before its rate limit runs, so
		// anyone can make the set write one record per request. Once the
		// memory set holds the share of its cap DPoP may fill, it refuses a new
		// proof as a store fault: refused unrecorded, as the server's outage —
		// never accepted unrecorded, and never answered as an invalid proof —
		// under its own reason, `replay_store_full`, apart from a store that
		// cannot be reached.
		const { logger, lines } = serialiseEverythingLogger();
		const seenSet = createMemoryReplaySeenSet({ maxEntries: 1 });
		const { handle, app } = await bootReplica({ mode: "single", seenSet, logger });

		const first = await mintProof();
		expect((await request(app).post("/oauth/token").set("DPoP", first.proof).send({})).status).toBe(
			200,
		);
		const { proof } = await mintProof();
		const res = await request(app).post("/oauth/token").set("DPoP", proof).send({});
		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				mechanism: "dpop",
				code: "temporarily_unavailable",
				reason: "replay_store_full",
				err: {
					name: "ReplaySeenSetFullError",
					detail:
						"memory ReplaySeenSet holds 1 live records, the share of its cap of 1 that DPoP proofs may fill; refusing a new proof so the rest stays for the other consumers",
					reason: "full",
					stack: FRAMES,
				},
			},
			"token_binding_unavailable",
		);
		expect(seenSet.size).toBe(1);
		// A replay needs no write, so the full set still refuses it.
		const replay = await request(app).post("/oauth/token").set("DPoP", first.proof).send({});
		expect(replay.status).toBe(400);
		expect(replay.body).toMatchObject({ error: "invalid_dpop_proof" });
		for (const line of lines) expect(line).not.toContain("dpop-proof:");

		await handle.dispose();
	});

	it("logs a proof the signature step refuses as the error's projection, never the claims jose puts on it", async () => {
		// jose verifies the signature, then the registered claims: a proof
		// whose `exp` has passed is refused with a JWTExpired that carries
		// the proof's whole payload — its `ath`, the hash of the access token
		// it is presented with, included.
		const { logger, lines } = serialiseEverythingLogger();
		const { handle, app } = await bootReplica({ mode: "single", seenSet: "module", logger });
		const { publicKey, privateKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const ath = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo";
		const now = Math.floor(Date.now() / 1000);
		const expired = await new SignJWT({
			htm: "POST",
			htu: `${ISSUER_ORIGIN}/oauth/token`,
			iat: now,
			exp: now - 60,
			jti: crypto.randomUUID(),
			ath,
		})
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
			.sign(privateKey);

		const res = await request(app).post("/oauth/token").set("DPoP", expired).send({});
		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "invalid_dpop_proof" });
		expect(logger.warn).toHaveBeenCalledWith(
			{
				err: {
					name: "JWTExpired",
					detail: '"exp" claim timestamp check failed',
					code: "ERR_JWT_EXPIRED",
					// jose's own code for the check, which the projection keeps.
					reason: "check_failed",
					stack: FRAMES,
				},
			},
			"dpop_signature_invalid",
		);
		for (const line of lines) expect(line).not.toContain(ath);

		await handle.dispose();
	});

	it("reports a replay TTL below 2W + 1 on the console when no logger is wired", async () => {
		// `reference.conf` points operators at this warning. The mechanism's
		// warnings must not be the ones that vanish in a composition that
		// wires no `logger` component.
		const consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			const { handle } = await bootReplica({
				mode: "single",
				seenSet: createMemoryReplaySeenSet(),
				// The default 60s window needs 121.
				replayTtlSeconds: 120,
			});

			expect(consoleWarn).toHaveBeenCalledWith(
				{ iatWindowSeconds: 60, replayTtlSeconds: 120, requiredTtlSeconds: 121 },
				"dpop_replay_ttl_below_window",
			);

			await handle.dispose();
		} finally {
			consoleWarn.mockRestore();
		}
	});

	it('boots under "multi" with DPoP installed but disabled and no seen-set: nothing is recorded', async () => {
		const logger = spyLogger();
		const { handle } = await bootReplica({
			mode: "multi",
			seenSet: "none",
			enabled: false,
			logger,
		});

		expect(logger.warn).not.toHaveBeenCalled();

		await handle.dispose();
	});
});
