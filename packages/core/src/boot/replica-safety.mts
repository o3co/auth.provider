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
import { failureSummary } from "./failure-summary.mjs";
import { BootError } from "./types.mjs";

/**
 * Boot guard for in-process state that must be shared across replicas.
 *
 * Shared/durable stores never silently fall back to memory:
 * `core.deployment.mode = "multi"` with a replica-unsafe module refuses boot,
 * `"single"` is silent, unset warns (see {@link checkReplicaSafety}).
 * Node-local storage (LocalFile/SQLite) is no safe default either: it diverges
 * across replicas and is ephemeral in a container.
 *
 * A module declares `replicaSafety: { unsafe: true, reason }` on its own
 * manifest, and the guard reads that off every installed module, not off the
 * config: a composition root can wire modules directly, or with a config that
 * names none of the adapter keys, and its own modules must be covered too.
 * A module whose section decides what it holds declares a function of that
 * section instead; stage 1 reads it once ({@link readReplicaSafety}), right
 * after the parse, and hands the guard the declaration it answered.
 */

/**
 * The module manifest fields the guard reads. A full `Module` satisfies it;
 * so does a name-only reference, which is answered from core's bundled
 * declarations (see {@link replicaUnsafeReason}). `section` is the manifest's
 * section declaration, read only for whether there is one: a declaration made
 * from the section is handed `undefined` for a module without one, and needs
 * the parsed section of a module with one.
 */
export interface ReplicaSafetyModuleRef {
	readonly name: string;
	readonly section?: unknown;
	readonly replicaSafety?: Module["replicaSafety"];
}

/**
 * The parsed section a declaration made from the section is answered for:
 * `{ value }`, or `undefined` when none was given — which a module with a
 * section cannot be answered without.
 */
export type GivenSection = { readonly value: unknown } | undefined;

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

/**
 * A `Map`, so a module named "toString" or "constructor" cannot match a
 * prototype key. Core's bundled modules declare statically: their state does
 * not depend on their section.
 */
const BUNDLED_REASONS_BY_NAME: ReadonlyMap<string, string> = new Map(
	REPLICA_UNSAFE_BUNDLED_MODULES.flatMap((m) => {
		const declared = m.replicaSafety;
		return typeof declared === "object" && declared.unsafe === true
			? [[m.name, declared.reason] as const]
			: [];
	}),
);

/**
 * Names of core's bundled modules that {@link checkReplicaSafety} refuses in
 * multi-replica mode. Core's modules only: to check a composition root's own
 * modules, ask each manifest via {@link replicaUnsafeReason}.
 */
export const REPLICA_UNSAFE_MODULES: readonly string[] = [...BUNDLED_REASONS_BY_NAME.keys()];

/**
 * A declaration made from the section, callable with the section as boot
 * holds it: the erased `Module` types its parameter `never`.
 */
const fromSection = (declared: (section: never) => unknown) =>
	declared as (section: unknown) => unknown;

/**
 * The one reading of `module`'s declaration: a static one as written; a
 * function's answer for the module's parsed section, called once and copied
 * into a frozen declaration. A module without a section is handed `undefined`
 * whatever `given` is. A module with one and no section `given`, a throw, or
 * an answer that is neither `undefined` nor `{ unsafe: true, reason }` with a
 * non-empty string `reason`, is a `problem`: the function is not called
 * without its section.
 */
export function readReplicaSafety(
	module: ReplicaSafetyModuleRef,
	given: GivenSection,
): { readonly declaration: ReplicaSafetyDeclaration | undefined } | { readonly problem: string } {
	const declared = module.replicaSafety;
	if (typeof declared !== "function") return { declaration: declared };
	const hasSection = module.section !== undefined;
	if (hasSection && given === undefined) {
		return { problem: "it is made from the module's section, and no parsed section was given" };
	}
	try {
		const answer = fromSection(declared).call(module, hasSection ? given?.value : undefined);
		if (answer === undefined) return { declaration: undefined };
		if (typeof answer === "object" && answer !== null) {
			const { unsafe, reason } = answer as Record<string, unknown>;
			if (unsafe === true && typeof reason === "string" && reason !== "") {
				return { declaration: Object.freeze({ unsafe, reason }) };
			}
		}
		return { problem: "it answered neither undefined nor { unsafe: true, reason } with a reason" };
	} catch (thrown) {
		return { problem: `it threw: ${failureSummary(thrown)}` };
	}
}

/** The problem {@link readReplicaSafety} found, as the error a public reader throws. */
const problemError = (module: ReplicaSafetyModuleRef, problem: string): TypeError =>
	new TypeError(`module "${module.name}"'s replicaSafety did not answer: ${problem}`);

/**
 * What diverges per replica for `module`, or `undefined` when the guard does
 * not refuse it. The manifest's declaration answers first, read as boot reads
 * it ({@link readReplicaSafety}); a name-only reference is answered from
 * core's bundled declarations.
 *
 * A declaration made from the section is answered for `section`, the module's
 * parsed section; called without one, for a module that has a section, it
 * throws a `TypeError` naming the module rather than guess. It throws the same
 * for a declaration that throws or answers a malformed value.
 */
export function replicaUnsafeReason(module: ReplicaSafetyModuleRef): string | undefined;
export function replicaUnsafeReason(
	module: ReplicaSafetyModuleRef,
	section: unknown,
): string | undefined;
export function replicaUnsafeReason(
	module: ReplicaSafetyModuleRef,
	...section: [] | [unknown]
): string | undefined {
	return reasonFor(module, section.length === 0 ? undefined : { value: section[0] });
}

function reasonFor(module: ReplicaSafetyModuleRef, given: GivenSection): string | undefined {
	const read = readReplicaSafety(module, given);
	if ("problem" in read) throw problemError(module, read.problem);
	if (read.declaration?.unsafe === true) return read.declaration.reason;
	return BUNDLED_REASONS_BY_NAME.get(module.name);
}

export interface CheckReplicaSafetyInput {
	readonly modules: readonly ReplicaSafetyModuleRef[];
	/**
	 * Parsed application config; only `core.deployment.mode` is read, with
	 * `deploymentModeOf` — the reading boot fills the `deploymentMode` slot
	 * with.
	 */
	readonly config: unknown;
	/**
	 * Each module's parsed section, by module name, for the declarations made
	 * from the section. A module with a section and such a declaration, and
	 * no entry here, is refused (a `TypeError` naming it). Boot hands the guard
	 * declarations it has read already, and no sections.
	 */
	readonly sections?: ReadonlyMap<string, unknown>;
	readonly logger?: Logger;
}

/**
 * Composition-root guard for replica-unsafe state, keyed on `core.deployment.mode`
 * as the `deploymentMode` slot holds it:
 *   - `multi`: boot fails naming every offender.
 *   - `single`: silent. Warning here would fire on every local run and train
 *     people to ignore the warning that matters.
 *   - `unset`: one consolidated warning naming each in-memory store and its cost.
 *
 * `core.deployment.mode` therefore has no HOCON default; one would make the unset
 * state unreachable. An operator who scales without setting the mode cannot be
 * detected: a process whose state is all in its own memory cannot see peers.
 */
export function checkReplicaSafety({
	modules,
	config,
	sections,
	logger,
}: CheckReplicaSafetyInput): void {
	const offenders = modules.flatMap((m) => {
		const reason = reasonFor(
			m,
			sections?.has(m.name) === true ? { value: sections.get(m.name) } : undefined,
		);
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
			message: `core.deployment.mode is "multi" but ${offenders.length === 1 ? "an in-memory store is" : `${offenders.length} in-memory stores are`} wired, which cannot be shared across replicas. Wire the Redis-backed equivalents, or set core.deployment.mode = "single". Offenders — ${reasons.join("; ")}`,
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
