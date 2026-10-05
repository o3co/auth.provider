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
import type { GrantHandler } from "./types.mjs";

export type GrantRegistryErrorReason = "duplicate" | "unknown" | "frozen";

/**
 * Error for GrantRegistry mutation failures. `registered` snapshots what is
 * registered, so the message shows where the caller's expectation was wrong.
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
 * - `register(name, handler)` throws on duplicate (no silent overwrite).
 * - `replace(name, handler)` is the explicit override path.
 * - `freeze()` is the activation boundary; after it, mutation throws.
 * - A `null` handler is a grant switched off by its module's settings: it
 *   claims the grant type (`has`, a second `register` is a duplicate) and is
 *   absent from `get` and `entries`, as a grant type nothing registered is.
 *
 * Only the boot planner mutates it, from each module's `contributes.grants`
 * and `overrides.grants`. Not in `@o3co/auth-provider-core`'s main entry
 * (only `/testing` re-exports it); consumers contribute grants through modules.
 *
 * @internal
 */
export class GrantRegistry {
	private handlers = new Map<string, GrantHandler | null>();
	private frozen = false;

	register(grantType: string, handler: GrantHandler | null): void {
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

	replace(grantType: string, handler: GrantHandler | null): void {
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
	 * reason "frozen"; get and entries continue to work.
	 */
	freeze(): void {
		this.frozen = true;
	}

	/** Whether the grant type is registered: with a handler, or switched off (`null`). */
	has(grantType: string): boolean {
		return this.handlers.has(grantType);
	}

	/** The grant type's handler; `undefined` when it is unregistered or switched off. */
	get(grantType: string): GrantHandler | undefined {
		return this.handlers.get(grantType) ?? undefined;
	}

	/**
	 * Every registered handler, in registration order; a replaced one keeps
	 * the place of the handler it replaced, and a switched-off grant type is
	 * left out. Readable before and after `freeze()`. Boot's `grants`
	 * collector hands this to the `grantHandlerResolver` it projects.
	 */
	*entries(): IterableIterator<readonly [string, GrantHandler]> {
		for (const [grantType, handler] of this.handlers) {
			if (handler !== null) yield [grantType, handler] as const;
		}
	}
}
