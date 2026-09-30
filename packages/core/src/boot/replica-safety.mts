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

import { memoryAccessTokenDenylistModule } from "../access-token-denylist/module.mjs";
import { memoryChallengeStoreModule } from "../challenges/module.mjs";
import { memoryConsentStoreModule } from "../consents/module.mjs";
import { deploymentModeOf } from "../deployment/mode.mjs";
import { memoryDeviceCodeStoreModule } from "../device-authorization/module.mjs";
import {
	memoryFederationGrantIntentStoreModule,
	memoryFederationGrantStoreModule,
} from "../federation-grants/module.mjs";
import { memoryFederationTokenStoreModule } from "../federation-tokens/module.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { memoryMfaFactorStoreModule, memoryMfaTransactionStoreModule } from "../mfa/module.mjs";
import type { Module, ReplicaSafetyDeclaration } from "../modules/manifest/index.mjs";
import { memoryRateLimiterModule } from "../ratelimit/module.mjs";
import { memoryRefreshTokenFamilyStoreModule } from "../refresh-token-family/module.mjs";
import { memoryReplaySeenSetModule } from "../replay-seen-set/module.mjs";
import { memorySessionStoresModule } from "../user-sessions/modules/memory.mjs";
import { memoryWebAuthnCredentialStoreModule } from "../webauthn-credentials/module.mjs";
import { BootError } from "./types.mjs";

/**
 * Boot guard for in-process state that must be shared across replicas.
 *
 * Shared/durable stores never silently fall back to memory:
 * `deployment.mode = "multi"` with a replica-unsafe module refuses boot,
 * `"single"` is silent, unset warns (see {@link checkReplicaSafety}).
 * Node-local storage (LocalFile/SQLite) is no safe default either: it diverges
 * across replicas and is ephemeral in a container.
 *
 * A module declares `replicaSafety: { unsafe: true, reason }` on its own
 * manifest, and the guard reads that off every installed module, not off the
 * config: a composition root can wire modules directly, or with a config that
 * names none of the adapter keys, and its own modules must be covered too.
 */

/**
 * The module manifest fields the guard reads. A full `Module` satisfies it;
 * so does a name-only reference, which is answered from core's bundled
 * declarations (see {@link replicaUnsafeReason}).
 */
export interface ReplicaSafetyModuleRef {
	readonly name: string;
	readonly replicaSafety?: ReplicaSafetyDeclaration;
}

/**
 * Core's bundled modules that declare `replicaSafety`. The guard reads every
 * installed manifest; this list backs {@link REPLICA_UNSAFE_MODULES} and
 * answers name-only references. `replica-safety.drift.test.mts` pins it to
 * exactly the core modules whose manifests declare.
 */
export const REPLICA_UNSAFE_BUNDLED_MODULES: readonly Module[] = [
	memorySessionStoresModule,
	memoryRateLimiterModule,
	memoryAccessTokenDenylistModule,
	memoryReplaySeenSetModule,
	memoryRefreshTokenFamilyStoreModule,
	memoryChallengeStoreModule,
	memoryWebAuthnCredentialStoreModule,
	memoryDeviceCodeStoreModule,
	memoryFederationTokenStoreModule,
	memoryConsentStoreModule,
	memoryFederationGrantStoreModule,
	memoryFederationGrantIntentStoreModule,
	memoryMfaFactorStoreModule,
	memoryMfaTransactionStoreModule,
];

/** A `Map`, so a module named "toString" or "constructor" cannot match a prototype key. */
const BUNDLED_REASONS_BY_NAME: ReadonlyMap<string, string> = new Map(
	REPLICA_UNSAFE_BUNDLED_MODULES.flatMap((m) =>
		m.replicaSafety?.unsafe === true ? [[m.name, m.replicaSafety.reason] as const] : [],
	),
);

/**
 * Names of core's bundled modules that {@link checkReplicaSafety} refuses in
 * multi-replica mode. Core's modules only: to check a composition root's own
 * modules, ask each manifest via {@link replicaUnsafeReason}.
 */
export const REPLICA_UNSAFE_MODULES: readonly string[] = [...BUNDLED_REASONS_BY_NAME.keys()];

/**
 * What diverges per replica for `module`, or `undefined` when the guard does
 * not refuse it. The manifest's declaration answers first; a name-only
 * reference is answered from core's bundled declarations.
 */
export function replicaUnsafeReason(module: ReplicaSafetyModuleRef): string | undefined {
	if (module.replicaSafety?.unsafe === true) return module.replicaSafety.reason;
	return BUNDLED_REASONS_BY_NAME.get(module.name);
}

export interface CheckReplicaSafetyInput {
	readonly modules: readonly ReplicaSafetyModuleRef[];
	/**
	 * Parsed application config; only `deployment.mode` is read, with
	 * `deploymentModeOf` — the reading boot fills the `deploymentMode` slot
	 * with.
	 */
	readonly config: unknown;
	readonly logger?: Logger;
}

/**
 * Composition-root guard for replica-unsafe state, keyed on `deployment.mode`
 * as the `deploymentMode` slot holds it:
 *   - `multi`: boot fails naming every offender.
 *   - `single`: silent. Warning here would fire on every local run and train
 *     people to ignore the warning that matters.
 *   - `unset`: one consolidated warning naming each in-memory store and its cost.
 *
 * `deployment.mode` therefore has no HOCON default; one would make the unset
 * state unreachable. An operator who scales without setting the mode cannot be
 * detected: a process whose state is all in its own memory cannot see peers.
 */
export function checkReplicaSafety({ modules, config, logger }: CheckReplicaSafetyInput): void {
	const offenders = modules.flatMap((m) => {
		const reason = replicaUnsafeReason(m);
		return reason === undefined ? [] : [{ name: m.name, reason }];
	});
	if (offenders.length === 0) return;

	const mode = deploymentModeOf(config);
	const names = offenders.map((o) => o.name);
	const reasons = offenders.map((o) => `${o.name}: ${o.reason}`);

	if (mode === "multi") {
		throw new BootError({
			stage: "validateManifests",
			reason: "replica-unsafe-adapter",
			message: `deployment.mode is "multi" but ${offenders.length === 1 ? "an in-memory store is" : `${offenders.length} in-memory stores are`} wired, which cannot be shared across replicas. Wire the Redis-backed equivalents, or set deployment.mode = "single". Offenders — ${reasons.join("; ")}`,
			details: { reason: "replica-unsafe-adapter", modules: names },
		});
	}

	if (mode === "single") return;

	logger?.warn(
		{ modules: names, reasons },
		// One event, all offenders: an operator reading boot logs should get the
		// whole picture in one line rather than reconstructing it from N.
		"replica_unsafe_adapters",
	);
}
