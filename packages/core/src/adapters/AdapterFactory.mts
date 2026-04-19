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
