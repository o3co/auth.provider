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
 * Bundled modules that hold state in this process's memory which **must** be
 * shared for a deployment to run more than one replica correctly (#271).
 *
 * Keyed by module name rather than by config, deliberately. The config
 * switches (`rateLimiter.adapter`, `userSessionStores.adapter`, …) are how
 * these modules get *selected* in the bundled composition, but a composition
 * root can wire a module directly, or hand-build a config that names none of
 * those keys. What is actually installed is the fact worth checking; what the
 * config says is a proxy for it.
 *
 * Each entry names what diverges, because "use redis" is not by itself a
 * reason and an operator triaging a boot warning deserves the consequence.
 */
const REPLICA_UNSAFE_MODULE_REASONS: Readonly<Record<string, string>> = {
	memorySessionStores:
		"user sessions, RP registrations, family indexes and the subject-level revocation pair fork per replica — back-channel logout reaches only the replica that received it, so a logged-out session stays valid on the others, and a credential change enumerates and watermarks only the replica that handled it (#321)",
	"core-rate-limiter-memory":
		"rate-limit counters fork per replica — every configured limit is effectively multiplied by the replica count, and resets on each deploy",
	"core-access-token-denylist-memory":
		"access-token revocation forks per replica — a revoked token keeps working on every replica that did not receive the revocation",
	"core-replay-seen-set-memory":
		"DPoP proof-replay detection forks per replica — a captured proof can be replayed once against each replica",
	"core-refresh-token-family-store-memory":
		"refresh-token families fork per replica — rotation replay detection and cascade revoke see only this replica's history",
	"core-challenge-store-memory":
		"WebAuthn challenges fork per replica — a ceremony started on one replica cannot be completed on another",
	"core-webauthn-credential-store-memory":
		"registered WebAuthn credentials fork per replica — a passkey registered on one replica does not exist on the others",
	"core-device-code-store-memory":
		"pending device authorizations fork per replica — the human approves a code on the replica that served the verification page, while the device polls a replica that has never heard of it and is told the code does not exist (#298)",
	"core-federation-token-store-memory":
		"upstream federation tokens fork per replica — a token stored on one replica is missing on the others",
};

/**
 * Names of the modules {@link checkReplicaSafety} refuses in multi-replica
 * mode. Exported so a composition root can run the same check itself, and so
 * the set is greppable from a deployment's own tests.
 */
export const REPLICA_UNSAFE_MODULES: readonly string[] = Object.keys(REPLICA_UNSAFE_MODULE_REASONS);

/**
 * What diverges per replica for `moduleName`, or `undefined` when the module is
 * not one this guard refuses.
 *
 * Exported so the drift guard (#304) can check that every listed module has a
 * reason worth printing, and so a composition root running its own version of
 * this check can reuse the wording rather than inventing a second vocabulary
 * for the same failure.
 */
export function replicaUnsafeReason(moduleName: string): string | undefined {
	return Object.hasOwn(REPLICA_UNSAFE_MODULE_REASONS, moduleName)
		? REPLICA_UNSAFE_MODULE_REASONS[moduleName]
		: undefined;
}

export interface CheckReplicaSafetyInput {
	readonly modules: readonly { readonly name: string }[];
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
	// `Object.hasOwn`, not `in`: `in` walks the prototype chain, so a module
	// named "toString" or "constructor" would match and then carry a function
	// where its reason text should be.
	const offenders = modules
		.map((m) => m.name)
		.filter((name) => Object.hasOwn(REPLICA_UNSAFE_MODULE_REASONS, name));
	if (offenders.length === 0) return;

	const mode = (config as { deployment?: { mode?: unknown } } | undefined)?.deployment?.mode;
	const reasons = offenders.map((name) => `${name}: ${REPLICA_UNSAFE_MODULE_REASONS[name]}`);

	if (mode === "multi") {
		throw new BootError({
			stage: "validateManifests",
			reason: "replica-unsafe-adapter",
			message: `deployment.mode is "multi" but ${offenders.length === 1 ? "an in-memory store is" : `${offenders.length} in-memory stores are`} wired, which cannot be shared across replicas. Wire the Redis-backed equivalents, or set deployment.mode = "single". Offenders — ${reasons.join("; ")}`,
			details: { reason: "replica-unsafe-adapter", modules: offenders },
		});
	}

	if (mode === "single") return;

	logger?.warn(
		{ modules: offenders, reasons },
		// One event, all offenders: an operator reading boot logs should get the
		// whole picture in one line rather than reconstructing it from N.
		"replica_unsafe_adapters",
	);
}
