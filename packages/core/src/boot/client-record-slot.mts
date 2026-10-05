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
 * boot/client-record-slot.mts: what boot does for the `clientRepository`
 * slot. Whatever fills it — a host's bootstrap or override value, or a
 * provider's — the slot holds core's client-record boundary over it
 * (`validatedClientRepository`), so every reader of `deps.clientRepository`
 * reads validated, frozen records and a refused one as the lookup's
 * rejection, without knowing the boundary exists. The boundary itself is
 * `repositories/`'s; this file only decides where it is installed.
 */

import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { EventLogger, Logger } from "../logging/Logger.mjs";
import type { ComponentKey } from "../modules/manifest/component-map.mjs";
import type { ClientRepository } from "../repositories/ClientRepository.mjs";
import { validatedClientRepository } from "../repositories/clientRepositoryBoundary.mjs";

/** What stage 3 does to the `clientRepository` slot. */
export interface ClientRecordSlot {
	/** Before any provider runs: puts the boundary over a host's value in the slot. */
	beforeProviders(): void;
	/** The value the working map holds for a provider's `value` under `key`. */
	provided(key: ComponentKey, value: unknown): unknown;
}

/**
 * Stage 3's handling of the `clientRepository` slot in `components`, the
 * working map. The slot holds the boundary over whatever fills it: a host's
 * value (bootstrap or override) before any provider runs, a provider's as it
 * is materialised. Every value but `null` and `undefined` is wrapped, a
 * callable or a primitive carrying the port's methods included, so nothing
 * that answers lookups reaches a reader around the boundary; an empty slot
 * stays empty, for stage 1's rules to have judged.
 *
 * - **One boundary.** A boundary already in the slot (one the host built
 *   with `validatedClientRepository`) is kept as it is, never wrapped twice,
 *   so it keeps its own logger; a reader that wraps the slot again gets the
 *   same object back.
 * - **The logger.** A refusal is warned through the `logger` component the
 *   map holds when the refusal happens, else `consoleLogger`.
 * - **Lifecycle.** Wrapping reads nothing of the value, so a value whose
 *   reads throw is installed as any other. A provider's cleanup is still
 *   handed its own value. Disposing the boundary disposes the value it wraps
 *   when that has a `Symbol.asyncDispose`, read at dispose, so boot's
 *   dispose reaches it as it would unwrapped; a host's value is still never
 *   disposed by boot.
 */
export function clientRecordSlotFor(components: Record<string, unknown>): ClientRecordSlot {
	const logger: Pick<EventLogger, "warn"> = {
		warn: (fields, message) =>
			((components.logger as Logger | undefined) ?? consoleLogger).warn(fields, message),
	};
	const behindBoundary = (value: unknown): unknown =>
		value === null || value === undefined
			? value
			: validatedClientRepository(value as ClientRepository, { logger });
	return {
		beforeProviders() {
			if (Object.hasOwn(components, "clientRepository")) {
				components.clientRepository = behindBoundary(components.clientRepository);
			}
		},
		provided(key, value) {
			return key === "clientRepository" ? behindBoundary(value) : value;
		},
	};
}
