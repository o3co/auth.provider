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
 * boot/audit-fan-out.mts: what boot does for `auditHooks`. When a module
 * contributes one, the `auditSink` slot holds core's fan-out
 * (`createAuditFanOut`) over the slot's own sink and every hook, so each
 * reader of `deps.auditSink` reaches them all without knowing hooks exist.
 * Stage 1 counts the slot as filled; stage 3 puts the fan-out in it; stage 4
 * registers the hooks it reads at each event.
 */

import { createAuditFanOut } from "../audit/factory.mjs";
import type { AuditSink } from "../audit/types.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { BootPlan, ContributionCollectorMap, NormalisedModule } from "./types.mjs";
import { BootError } from "./types.mjs";

/** Whether any module contributes an `auditHooks` entry: then core fills `auditSink`. */
export function contributesAuditHooks(modules: readonly NormalisedModule[]): boolean {
	return modules.some((m) => m.contributesEntries.some((entry) => entry.kind === "auditHooks"));
}

/**
 * Stage-1 row: a module that contributes `auditHooks` may not read
 * `auditSink`, in `requires` or `optional`. Its hooks are handed every event
 * the slot records, so an event it emitted from one would be handed back to
 * it. Refused as a `circular-dependency` of the module on itself.
 */
export function checkAuditHooksDoNotReadAuditSink(modules: readonly NormalisedModule[]): void {
	for (const m of modules) {
		const reads = [...m.requires, ...m.optional].includes("auditSink");
		if (!reads || !contributesAuditHooks([m])) continue;
		throw new BootError({
			message:
				`Module "${m.name}" contributes auditHooks and reads auditSink, which hands every ` +
				"event to those hooks: an event emitted from one of its hooks would come back to it. " +
				"Contribute the hooks from a module that does not list auditSink in requires or optional.",
			reason: "circular-dependency",
			stage: "validateManifests",
			details: {
				reason: "circular-dependency",
				cycle: [{ module: m.name, requires: "auditSink", satisfiedBy: m.name }],
			},
		});
	}
}

/**
 * Stage 3: when a module contributes `auditHooks`, the function that turns
 * the slot's own sink (or none) into the value `auditSink` holds; otherwise
 * `undefined`, and the slot holds what fills it, as it is. The hooks are read
 * from the `auditHooks` collector at each event, and a failing sink is
 * reported to the `logger` component `components` holds at that moment.
 *
 * Disposing the fan-out disposes the slot's own sink when that sink has a
 * `Symbol.asyncDispose`, so boot's dispose reaches it as it would unwrapped.
 * The hooks are contributions and are not disposed.
 */
export function auditFanOutFor(
	plan: BootPlan,
	contributionKinds: ContributionCollectorMap,
	components: Readonly<Record<string, unknown>>,
): ((sink: unknown) => AuditSink) | undefined {
	if (!contributesAuditHooks(plan.validated.modules.map((m) => m.normalised))) return undefined;
	const hooks = (): Iterable<AuditSink> => {
		const collector = contributionKinds.auditHooks;
		return collector?.kind === "list" ? collector.values() : [];
	};
	const logger = () => components.logger as Logger | undefined;
	return (sink) => {
		const own = sink === undefined || sink === null ? undefined : (sink as AuditSink);
		const fanOut = createAuditFanOut({
			...(own === undefined ? {} : { sink: own }),
			hooks,
			logger,
		});
		const dispose = (own as { [Symbol.asyncDispose]?: unknown } | undefined)?.[Symbol.asyncDispose];
		if (typeof dispose !== "function") return fanOut;
		return { ...fanOut, [Symbol.asyncDispose]: () => dispose.call(own) };
	};
}
