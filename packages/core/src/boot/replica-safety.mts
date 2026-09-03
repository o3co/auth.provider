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
import { memoryDeviceCodeStoreModule } from "../device-authorization/module.mjs";
import { memoryFederationTokenStoreModule } from "../federation-tokens/module.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { Module, ReplicaSafetyDeclaration } from "../modules/manifest/index.mjs";
import { memoryRateLimiterModule } from "../ratelimit/module.mjs";
import { memoryRefreshTokenFamilyStoreModule } from "../refresh-token-family/module.mjs";
import { memoryReplaySeenSetModule } from "../replay-seen-set/module.mjs";
import { memorySessionStoresModule } from "../user-sessions/modules/memory.mjs";
import { memoryWebAuthnCredentialStoreModule } from "../webauthn-credentials/module.mjs";
import { BootError } from "./types.mjs";

/**
 * ## The default-adapter policy this file enforces (#304)
 *
 * #304 asked for the policy to be pinned "so implementers don't reintroduce
 * unsafe defaults". Recording it here, next to the enforcement, with what each
 * clause resolved to:
 *
 * 1. **Sinks never default to silence.** Answered by #363 rather than by a
 *    stdout default: an unfilled `auditSink` refuses boot unless the config
 *    declares the capability absent (`audit.sink.type = "none"`). Stronger
 *    than defaulting to stdout, which would hand a sink to a composition root
 *    that never asked for one and call that safety. Same shape now covers the
 *    access-token denylist (#375) and subject-level revocation (#406).
 * 2. **Shared/durable state stores never silently fall back to memory.** This
 *    file. `deployment.mode = "multi"` with an in-process store wired refuses
 *    to boot; `"single"` is silent; unset warns. There is deliberately no
 *    HOCON default, so the unset state stays reachable — see
 *    {@link checkReplicaSafety}.
 * 3. **`LocalFile`/`SQLite` is not a global default.** Node-local storage does
 *    not fix what `memory` gets wrong across replicas, and is ephemeral in a
 *    container. It would be a legitimate default for a single-node profile,
 *    which needs an adapter that does not exist yet — separate work, as #304
 *    itself notes.
 *
 * The profile names differ from #304's sketch (`single` / `multi`, not
 * `dev` / `single-node` / `multi-replica`): the two shipped with #271 and
 * renaming them would break every deployment that has declared its shape, to
 * buy a third name for a profile whose adapter does not exist.
 *
 * ## Where the declaration lives (#455)
 *
 * A module says on its own manifest that it holds state in this process's
 * memory which **must** be shared for a deployment to run more than one
 * replica correctly (#271): `replicaSafety: { unsafe: true, reason }`. The
 * guard reads that off every installed manifest.
 *
 * It used to read a table of module names kept in this file. The table was
 * written against core's modules (#304), and the standalone template wires
 * its *own* in-memory modules under names the table had never heard of —
 * `standalone:in-memory-session-stores`, `standalone:in-memory-code-repository`,
 * the memory federation store — so `deployment.mode = "multi"` booted with
 * exactly the stores that fork per replica the worst (#455). Two vocabularies
 * for "this module holds state in memory", one guard. The manifest is where
 * the module is, so the manifest is where the fact is declared, and a
 * composition root's module is covered the day it is written.
 *
 * Read off the installed modules rather than the config, deliberately. The
 * config switches (`rateLimiter.adapter`, `userSessionStores.adapter`, …) are
 * how these modules get *selected* in the bundled composition, but a
 * composition root can wire a module directly, or hand-build a config that
 * names none of those keys. What is actually installed is the fact worth
 * checking; what the config says is a proxy for it.
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
 * Core's bundled modules that declare `replicaSafety` on their manifest.
 *
 * This list is not what the guard checks — the guard reads every installed
 * manifest, including a composition root's own. It exists so
 * {@link REPLICA_UNSAFE_MODULES} can still be exported for deployments that
 * assert on the set from their tests, and so a caller handing in name-only
 * references still gets core's answer. The drift guard
 * (`replica-safety.drift.test.mts`) pins it to exactly the core modules whose
 * manifests declare, so adding a tenth memory module without listing it here
 * is a failing test rather than a quietly incomplete export.
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
];

/**
 * A `Map`, not a plain object: `Object.hasOwn` was needed on the old table so
 * that a module named "toString" or "constructor" did not match a prototype
 * key and carry a function where its reason text should be. A `Map` has no
 * prototype keys to collide with.
 */
const BUNDLED_REASONS_BY_NAME: ReadonlyMap<string, string> = new Map(
	REPLICA_UNSAFE_BUNDLED_MODULES.flatMap((m) =>
		m.replicaSafety?.unsafe === true ? [[m.name, m.replicaSafety.reason] as const] : [],
	),
);

/**
 * Names of core's bundled modules that {@link checkReplicaSafety} refuses in
 * multi-replica mode. Exported so the set is greppable from a deployment's
 * own tests.
 *
 * Since #455 this is derived from the modules' own manifests rather than
 * maintained here, and it covers **core's** modules only: a composition
 * root's module declares `replicaSafety` on itself and is refused by the
 * guard without appearing in this list. A deployment asserting that nothing
 * replica-unsafe is wired should ask each manifest — `replicaUnsafeReason(m)`
 * — rather than this list.
 */
export const REPLICA_UNSAFE_MODULES: readonly string[] = [...BUNDLED_REASONS_BY_NAME.keys()];

/**
 * What diverges per replica for `module`, or `undefined` when it is not one
 * this guard refuses.
 *
 * The manifest's own declaration answers first. A name-only reference — a
 * normalised module list, a test handing in `{ name }` — is answered from
 * core's bundled declarations, so a composition root running its own version
 * of this check gets the same wording either way rather than inventing a
 * second vocabulary for the same failure.
 */
export function replicaUnsafeReason(module: ReplicaSafetyModuleRef): string | undefined {
	if (module.replicaSafety?.unsafe === true) return module.replicaSafety.reason;
	return BUNDLED_REASONS_BY_NAME.get(module.name);
}

export interface CheckReplicaSafetyInput {
	readonly modules: readonly ReplicaSafetyModuleRef[];
	/** Parsed application config; only `deployment.mode` is read. */
	readonly config: unknown;
	readonly logger?: Logger;
}

/**
 * Composition-root guard for replica-unsafe state (#271).
 *
 * Three states, because "is this deployment scaled?" has three honest answers
 * and collapsing them to two makes one of them useless:
 *
 *   - **`deployment.mode = "multi"`** — the operator has said there is more
 *     than one replica, so any in-memory shared state is a defect and boot
 *     fails naming every offender.
 *   - **`deployment.mode = "single"`** — the operator has said there is one.
 *     In-memory state is correct and this says nothing. Warning anyway would
 *     fire on every local run and train people to ignore the warning that
 *     matters.
 *   - **unset** — nothing has been said. This is where the 3am scenario starts,
 *     so it is the state that has to be loud: one consolidated warning naming
 *     what is in memory and what each one costs when scaled.
 *
 * Which is why `deployment.mode` has **no literal default in HOCON**. A baked-in
 * `"single"` would make the unset state unreachable and the warning dead code.
 *
 * **This cannot catch the operator who scales without ever setting
 * `deployment.mode`** — the case the issue describes. A process whose state is
 * entirely in its own memory has no shared medium through which to observe
 * peers, so the condition is undetectable from inside precisely when it is
 * true. The warning and the documentation are what address that; the failure
 * mode is for operators who have declared their shape.
 */
export function checkReplicaSafety({ modules, config, logger }: CheckReplicaSafetyInput): void {
	const offenders = modules.flatMap((m) => {
		const reason = replicaUnsafeReason(m);
		return reason === undefined ? [] : [{ name: m.name, reason }];
	});
	if (offenders.length === 0) return;

	const mode = (config as { deployment?: { mode?: unknown } } | undefined)?.deployment?.mode;
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
