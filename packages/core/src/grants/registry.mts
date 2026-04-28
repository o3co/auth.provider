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
import type { GrantDependencies, GrantHandler, GrantModule } from "./types.mjs";

export type GrantRegistryErrorReason = "duplicate" | "unknown" | "frozen";

/**
 * Error class for GrantRegistry mutation failures. Per A6+A7 §2.4.
 *
 * The `registered` snapshot lets callers see what is currently registered
 * so the diagnostic reveals the actual mental-model mismatch.
 */
export class GrantRegistryError extends Error {
	readonly reason: GrantRegistryErrorReason;
	readonly grantType: string;
	readonly registered: readonly string[];

	constructor(args: {
		reason: GrantRegistryErrorReason;
		grantType: string;
		registered: readonly string[];
	}) {
		const detail =
			args.reason === "duplicate"
				? `grant type "${args.grantType}" is already registered`
				: args.reason === "unknown"
					? `grant type "${args.grantType}" is not registered (cannot replace)`
					: `registry is frozen; cannot mutate "${args.grantType}"`;
		const registeredSuffix =
			args.registered.length > 0
				? `Registered: ${args.registered.join(", ")}.`
				: "Registered: (none).";
		super(`GrantRegistryError [${args.reason}]: ${detail}. ${registeredSuffix}`);
		this.name = "GrantRegistryError";
		this.reason = args.reason;
		this.grantType = args.grantType;
		this.registered = [...args.registered];
	}
}

/**
 * Registry of grant handlers, keyed by grant_type URN.
 *
 * Per A6+A7 §2.1–§2.3 (v0.5.0 unified contract):
 * - `register(name, handler)` throws on duplicate (no silent overwrite).
 * - `replace(name, handler)` is the explicit override path.
 * - `freeze()` is the activation boundary — after freeze, mutation throws.
 *
 * The boot planner (Phase 4 / A2-β) is the only intended caller of
 * `register` / `replace` / `freeze` in the v0.5.0 architecture, driving
 * them from each module's `contributes.grants` and `overrides.grants`
 * declarations. Phase 9 (A2-γ caller migration) internalises the registry
 * and removes it from the public API. Phase 3 establishes the contract.
 */
export class GrantRegistry {
	private handlers = new Map<string, GrantHandler>();
	private frozen = false;

	register(grantType: string, handler: GrantHandler): void {
		if (this.frozen) {
			throw new GrantRegistryError({
				reason: "frozen",
				grantType,
				registered: [...this.handlers.keys()],
			});
		}
		if (this.handlers.has(grantType)) {
			throw new GrantRegistryError({
				reason: "duplicate",
				grantType,
				registered: [...this.handlers.keys()],
			});
		}
		this.handlers.set(grantType, handler);
	}

	replace(grantType: string, handler: GrantHandler): void {
		if (this.frozen) {
			throw new GrantRegistryError({
				reason: "frozen",
				grantType,
				registered: [...this.handlers.keys()],
			});
		}
		if (!this.handlers.has(grantType)) {
			throw new GrantRegistryError({
				reason: "unknown",
				grantType,
				registered: [...this.handlers.keys()],
			});
		}
		this.handlers.set(grantType, handler);
	}

	/**
	 * Seal the registry. Idempotent: calling freeze() on an already-frozen
	 * registry is a no-op. After freeze, register and replace throw with
	 * reason "frozen"; get continues to work.
	 */
	freeze(): void {
		this.frozen = true;
	}

	get(grantType: string): GrantHandler | undefined {
		return this.handlers.get(grantType);
	}

	addModule(module: GrantModule, deps: GrantDependencies): void {
		// Apply configSchema defaults when provided.
		// Pre-fill missing top-level keys with {} so nested defaults are applied in a single parse.
		const effectiveDeps = module.configSchema
			? {
					...deps,
					config: {
						...deps.config,
						oauth: {
							...deps.config.oauth,
							grants: {
								...deps.config.oauth.grants,
								...(module.configSchema.parse(
									Object.fromEntries(
										Object.keys(module.grants).map((name) => [
											name,
											(deps.config.oauth.grants as Record<string, unknown>)[name] ?? {},
										]),
									),
								) as Record<string, unknown>),
							},
						},
					},
				}
			: deps;

		for (const [name, factory] of Object.entries(module.grants)) {
			const grantConfig = (
				effectiveDeps.config.oauth.grants as Record<string, { enabled?: boolean }>
			)[name];
			if (grantConfig?.enabled === false) continue;
			this.register(name, factory(effectiveDeps));
		}
	}

	cleanup(): void {
		for (const handler of this.handlers.values()) {
			handler.cleanup?.();
		}
	}
}
