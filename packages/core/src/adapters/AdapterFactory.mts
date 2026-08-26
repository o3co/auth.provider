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

import type { Logger } from "../logging/Logger.mjs";
import type { ReadinessRegistrar } from "../readiness/types.mjs";

/**
 * Passed to AdapterFactory builders via {@link BuilderContext.lifecycle}.
 * Builders that create disposable sub-resources (Redis clients, interval
 * timers, etc.) SHOULD register a cleanup callback here.
 *
 * Cleanups are invoked in LIFO order (reverse of registration) during
 * `AppHandle.dispose()`, with `await` between each (sequential, not parallel).
 * Errors in individual cleanups are logged and do NOT abort the drain. All
 * cleanup errors accumulate into the AggregateError that `AppHandle.dispose()`
 * may throw.
 */
export interface LifecycleRegistrar {
	/**
	 * Register a cleanup callback. Called in LIFO order during
	 * `AppHandle.dispose()`. The callback MUST return a Promise.
	 */
	register(cleanup: () => Promise<void>): void;
}

/**
 * Builder context passed to every adapter builder. All fields are optional
 * and additions remain additive-only (non-breaking). Builders may ignore
 * fields they do not need.
 *
 * Planned future fields:
 *   - logger?: Logger         (startup-time logging — see D-4 Logger interface)
 *   - abortSignal?: AbortSignal (timeout-aware init, e.g. database connections)
 *   - tracer?: Tracer         (OpenTelemetry context propagation)
 *   - metrics?: MetricsRecorder (metrics backend injection)
 */
export interface BuilderContext {
	/**
	 * Lifecycle registrar provided by the boot planner. Builders that produce
	 * a resource requiring cleanup (database client, interval timer, etc.)
	 * SHOULD call:
	 *
	 *     ctx.lifecycle?.register(async () => { await resource.close(); })
	 *
	 * Optional: factories constructed outside the boot planner (e.g. unit
	 * tests) receive `{}` as `ctx`, so `ctx.lifecycle` is `undefined`. Always
	 * use optional chaining.
	 */
	lifecycle?: LifecycleRegistrar;
	/**
	 * Readiness registrar provided by the boot planner. Builders that open a
	 * connection SHOULD register a probe for it:
	 *
	 *     ctx.readiness?.register({ name: "redis", check: () => client.ping() })
	 *
	 * Registration belongs here for the same reason cleanup does: the builder
	 * is the only place holding the connection. The adapter it returns exposes
	 * a narrow command surface with no `ping`, so a composition root cannot
	 * build the probe from the outside.
	 *
	 * Optional, and subject to the same optional-chaining rule as
	 * {@link BuilderContext.lifecycle}.
	 */
	readiness?: ReadinessRegistrar;
	/**
	 * Structured logger provided by the boot planner from the optional
	 * `logger` ComponentMap slot. Builders that attach an `error` listener to
	 * a connection they open report through it:
	 *
	 *     client.on("error", (err) => ctx.logger?.error({ err }, "…_error"))
	 *
	 * Same channel as `lifecycle` and `readiness` on purpose: a builder that
	 * opens a connection owns its cleanup, its probe, and its error listener,
	 * and having those three arrive by three different routes is how one of
	 * them gets forgotten. Falls back to `consoleLogger` when absent.
	 */
	logger?: Logger;
}

/**
 * Internal-LifecycleRegistrar with a `_drain` method for the boot planner.
 * The `_` prefix signals private use — only `AppHandle.dispose()` calls
 * `_drain`.
 */
export interface InternalLifecycleRegistrar extends LifecycleRegistrar {
	/**
	 * Drain all registered cleanups in LIFO order. Returns the array of
	 * errors encountered (empty if all cleanups succeeded). Each error is
	 * logged via the supplied logger as it occurs; the drain never throws.
	 *
	 * @internal
	 */
	_drain(logger: { error(obj: unknown): void }): Promise<readonly unknown[]>;
}

/**
 * Create a concrete LifecycleRegistrar backed by an ordered array.
 *
 * @internal — used by the boot planner; not part of the consumer-facing API.
 */
export function createLifecycleRegistrar(): InternalLifecycleRegistrar {
	const cleanups: Array<() => Promise<void>> = [];
	return {
		register(cleanup: () => Promise<void>): void {
			cleanups.push(cleanup);
		},
		async _drain(logger: { error(obj: unknown): void }): Promise<readonly unknown[]> {
			const errors: unknown[] = [];
			for (let i = cleanups.length - 1; i >= 0; i--) {
				const cleanup = cleanups[i];
				if (cleanup === undefined) continue;
				try {
					await cleanup();
				} catch (err) {
					logger.error({ msg: "lifecycle cleanup failed", cleanupIndex: i, error: err });
					errors.push(err);
				}
			}
			return errors;
		},
	};
}

/**
 * Factory builder function: given raw config plus a {@link BuilderContext}, produce
 * an adapter instance (sync or async).
 *
 * The `ctx` parameter is always a frozen snapshot captured at factory creation time;
 * builders must not assume they can mutate it.
 */
export type AdapterBuilder<T> = (
	config: Record<string, unknown>,
	ctx: Readonly<BuilderContext>,
) => T | Promise<T>;

/**
 * Name-based adapter registry. Consumers create one factory per "kind" (domain),
 * register a builder per concrete adapter type, and resolve an instance at startup
 * via {@link AdapterFactory.create}.
 *
 * Per A6+A7 §2.3: `AdapterFactory` is a composition-root concern and intentionally
 * has NO `freeze()` method. Infrastructure builder composition is not protocol-
 * module registration; there is no temporal boundary at which mutation becomes a
 * contract violation. Throw-on-duplicate `register` + explicit `replace` is
 * sufficient defence.
 */
export interface AdapterFactory<T> {
	/**
	 * Register a builder for `type`. Throws {@link AdapterFactoryError} with
	 * `reason: "duplicate"` if `type` is already registered (silent-override
	 * prevention). To intentionally override an existing registration, use
	 * {@link AdapterFactory.replace}.
	 */
	register(type: string, builder: AdapterBuilder<T>): void;

	/**
	 * Overwrite a previously-registered builder. Per A6+A7 §2.2.
	 *
	 * - If `type` is registered: replace the builder. Returns `void`.
	 * - If `type` is NOT registered: throws {@link AdapterFactoryError} with
	 *   `reason: "unknown-replace"`. Replacing a non-existent entry is an
	 *   error — the caller's mental model is wrong about what is registered.
	 *
	 * Security note: `replace()` has zero production callers at v0.5.0 and is
	 * intended exclusively for test-fixture override of built-in adapters
	 * (e.g., substituting a memory adapter for a Redis adapter in tests). The
	 * runtime security boundary is the resolved adapter instance returned by
	 * {@link AdapterFactory.create}, not this factory's builders map.
	 * Freezing this factory would protect an object already off the runtime
	 * path post-boot. See ADR:
	 * `.claude/audit/decisions/D-3-resolution.md` (D-3, 2026-05-05) for the
	 * full wrong-layer framing analysis and the explicit decision to close
	 * SF-11 by documentation, not by adding `freeze()`.
	 */
	replace(type: string, builder: AdapterBuilder<T>): void;

	/**
	 * Resolve an adapter from config. The `type` field selects the builder;
	 * the full config object (including `type`) is forwarded to the builder
	 * alongside the factory-level {@link BuilderContext}.
	 *
	 * Always returns `Promise<T>` regardless of whether the builder is sync or async.
	 */
	create(config: { type: string } & Record<string, unknown>): Promise<T>;

	/**
	 * Snapshot of currently registered type names. Used by error messages and tests.
	 */
	registeredTypes(): string[];
}

/**
 * Construct a fresh {@link AdapterFactory} for a single domain.
 *
 * @param kind human-readable label used in error messages (e.g. "UserRepository")
 * @param ctx  factory-level BuilderContext passed to every builder. Defaults to `{}`.
 */
export function createAdapterFactory<T>(kind: string, ctx: BuilderContext = {}): AdapterFactory<T> {
	const frozenCtx: Readonly<BuilderContext> = Object.freeze({ ...ctx });
	const builders = new Map<string, AdapterBuilder<T>>();

	return {
		register(type: string, builder: AdapterBuilder<T>): void {
			if (builders.has(type)) {
				throw new AdapterFactoryError({
					reason: "duplicate",
					kind,
					type,
					registered: [...builders.keys()],
				});
			}
			builders.set(type, builder);
		},

		replace(type: string, builder: AdapterBuilder<T>): void {
			if (!builders.has(type)) {
				throw new AdapterFactoryError({
					reason: "unknown-replace",
					kind,
					type,
					registered: [...builders.keys()],
				});
			}
			builders.set(type, builder);
		},

		async create(config: { type: string } & Record<string, unknown>): Promise<T> {
			const builder = builders.get(config.type);
			if (!builder) {
				throw new AdapterFactoryError({
					reason: "unknown",
					kind,
					type: config.type,
					registered: [...builders.keys()],
				});
			}
			return builder(config, frozenCtx);
		},

		registeredTypes(): string[] {
			return [...builders.keys()];
		},
	};
}

export type AdapterFactoryErrorReason = "unknown" | "duplicate" | "unknown-replace";

export class AdapterFactoryError extends Error {
	public readonly reason: AdapterFactoryErrorReason;
	public readonly kind: string;
	public readonly type: string;
	public readonly registered: readonly string[];

	constructor(args: {
		reason: AdapterFactoryErrorReason;
		kind: string;
		type: string;
		registered: readonly string[];
	}) {
		const registeredSuffix =
			args.registered.length > 0
				? `Registered types: ${args.registered.join(", ")}`
				: "No types registered";
		const detail =
			args.reason === "unknown"
				? `unknown type "${args.type}"`
				: args.reason === "duplicate"
					? `type "${args.type}" is already registered`
					: `cannot replace type "${args.type}" — not registered`;
		super(`AdapterFactoryError [${args.kind}]: ${detail}. ${registeredSuffix}`);
		this.name = "AdapterFactoryError";
		this.reason = args.reason;
		this.kind = args.kind;
		this.type = args.type;
		this.registered = [...args.registered];
	}
}
