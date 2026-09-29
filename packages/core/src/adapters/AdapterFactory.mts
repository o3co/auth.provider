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

import type { EventLogger, Logger } from "../logging/Logger.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import type { ReadinessRegistrar } from "../readiness/types.mjs";

/**
 * Passed to AdapterFactory builders via {@link BuilderContext.lifecycle}.
 * Builders that create disposable sub-resources (Redis clients, interval
 * timers) SHOULD register a cleanup here.
 *
 * `AppHandle.dispose()` runs cleanups sequentially in LIFO order. A failing
 * cleanup is logged and does not abort the drain; all failures accumulate
 * into the AggregateError `dispose()` may throw.
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
 * and additions stay additive (non-breaking); builders ignore fields they do
 * not need.
 */
export interface BuilderContext {
	/**
	 * Lifecycle registrar provided by the boot planner. Builders that produce
	 * a resource requiring cleanup SHOULD call:
	 *
	 *     ctx.lifecycle?.register(async () => { await resource.close(); })
	 *
	 * Optional: factories built outside the boot planner (e.g. unit tests)
	 * receive `{}` as `ctx`, so always use optional chaining.
	 */
	lifecycle?: LifecycleRegistrar;
	/**
	 * Readiness registrar provided by the boot planner. Builders that open a
	 * connection SHOULD register a probe for it:
	 *
	 *     ctx.readiness?.register({ name: "redis", check: () => client.ping() })
	 *
	 * Only the builder holds the connection; the adapter it returns has no
	 * `ping`, so a composition root cannot build the probe. Optional, like
	 * {@link BuilderContext.lifecycle}. See ADR
	 * 2026-08-26-readiness-probes-registered-by-connection-owners.
	 */
	readiness?: ReadinessRegistrar;
	/**
	 * Structured logger provided by the boot planner from the optional
	 * `logger` ComponentMap slot. Builders that attach an `error` listener to
	 * a connection they open report through it:
	 *
	 *     client.on("error", (err) => ctx.logger?.error({ err: loggableError(err) }, "…_error"))
	 *
	 * Same channel as `lifecycle` and `readiness`, so a builder gets its
	 * cleanup, probe and error listener in one place. Falls back to
	 * `consoleLogger` when absent.
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
	 * Drain all registered cleanups in LIFO order and return the errors.
	 * Each failure is logged once, at error, as
	 * `adapter_lifecycle_cleanup_failed` with
	 * `{ phase, cleanupIndex, err: loggableError(err) }`; `phase` says whether
	 * `AppHandle.dispose()` or a failed boot drained. Never throws, not even
	 * when the logger does.
	 *
	 * @internal
	 */
	_drain(
		logger: Pick<EventLogger, "error">,
		phase: "dispose" | "boot_failure",
	): Promise<readonly unknown[]>;
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
		async _drain(
			logger: Pick<EventLogger, "error">,
			phase: "dispose" | "boot_failure",
		): Promise<readonly unknown[]> {
			const errors: unknown[] = [];
			for (let i = cleanups.length - 1; i >= 0; i--) {
				const cleanup = cleanups[i];
				if (cleanup === undefined) continue;
				try {
					await cleanup();
				} catch (err) {
					errors.push(err);
					try {
						logger.error(
							{ phase, cleanupIndex: i, err: loggableError(err) },
							"adapter_lifecycle_cleanup_failed",
						);
					} catch {
						// A logger that cannot log must not cost the cleanups still
						// to run, nor replace the error a failed boot rethrows. The
						// failure itself is in the errors returned.
					}
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
 * Deliberately has no `freeze()`: a composition-root concern has no point after
 * which mutation becomes a contract violation. Throw-on-duplicate `register`
 * plus explicit `replace` is sufficient defence.
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
	 * Overwrite a previously registered builder. Throws
	 * {@link AdapterFactoryError} with `reason: "unknown-replace"` when `type`
	 * is not registered: the caller is wrong about what is registered.
	 *
	 * Intended for tests substituting a built-in adapter (e.g. memory for
	 * Redis). The runtime security boundary is the adapter instance
	 * {@link AdapterFactory.create} returns, not this builders map, which is
	 * off the runtime path after boot; freezing it would guard the wrong layer.
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
