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
 * Builder context passed to every adapter builder.
 *
 * Intentionally minimal in v1 — all fields are optional and future additions are
 * guaranteed to be additive-only (non-breaking). Builders may ignore fields they
 * do not need. Planned future fields:
 *   - logger?: Logger         (startup-time logging, added when logger injection lands)
 *   - abortSignal?: AbortSignal (timeout-aware init, e.g. database connections)
 *   - tracer?: Tracer         (OpenTelemetry context propagation)
 *   - metrics?: MetricsRecorder (metrics backend injection)
 */
// biome-ignore lint/suspicious/noEmptyInterface: intentionally empty in v1; interface (not type alias) preserves declaration-merging for additive evolution
export interface BuilderContext {}

/**
 * Factory builder function: given raw config plus a {@link BuilderContext}, produce
 * an adapter instance (sync or async).
 */
export type AdapterBuilder<T> = (
	config: Record<string, unknown>,
	ctx: BuilderContext,
) => T | Promise<T>;

/**
 * Name-based adapter registry. Consumers create one factory per "kind" (domain),
 * register a builder per concrete adapter type, and resolve an instance at startup
 * via {@link AdapterFactory.create}.
 */
export interface AdapterFactory<T> {
	/**
	 * Register a builder for `type`. Throws if `type` is already registered
	 * (silent-override prevention). Consumers needing override semantics must
	 * create a new factory instance.
	 */
	register(type: string, builder: AdapterBuilder<T>): void;

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
	const builders = new Map<string, AdapterBuilder<T>>();

	return {
		register(type: string, builder: AdapterBuilder<T>): void {
			if (builders.has(type)) {
				throw new Error(`AdapterFactory [${kind}]: type "${type}" is already registered`);
			}
			builders.set(type, builder);
		},

		async create(config: { type: string } & Record<string, unknown>): Promise<T> {
			const builder = builders.get(config.type);
			if (!builder) {
				throw new AdapterFactoryError({
					kind,
					type: config.type,
					registered: [...builders.keys()],
				});
			}
			return builder(config, ctx);
		},

		registeredTypes(): string[] {
			return [...builders.keys()];
		},
	};
}

export class AdapterFactoryError extends Error {
	public readonly kind: string;
	public readonly type: string;
	public readonly registered: readonly string[];

	constructor(args: { kind: string; type: string; registered: readonly string[] }) {
		const suffix =
			args.registered.length > 0
				? `Registered types: ${args.registered.join(", ")}`
				: "No types registered";
		super(`AdapterFactoryError [${args.kind}]: unknown type "${args.type}". ${suffix}`);
		this.name = "AdapterFactoryError";
		this.kind = args.kind;
		this.type = args.type;
		this.registered = [...args.registered];
	}
}
