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
 * registers the hooks it reads at each event and says which module
 * contributed each (`audit_hooks_registered`).
 */
import { createAuditFanOut } from "../audit/factory.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
/** Whether any module contributes an `auditHooks` entry: then core fills `auditSink`. */
export function contributesAuditHooks(modules) {
    return modules.some((m) => m.contributesEntries.some((entry) => entry.kind === "auditHooks"));
}
const UNTOUCHED = { beforeProviders: () => { }, provided: (_key, value) => value };
/**
 * Stage 3's handling of the `auditSink` slot in `components`, the working
 * map. Without an `auditHooks` contribution it leaves the slot as whatever
 * fills it. With one, the slot holds the fan-out over the host's sink, a
 * provider's, or none; the hooks are read from the `auditHooks` collector at
 * each event, and a failing sink is reported to the `logger` component the
 * map holds at that moment. A provider's cleanup is still handed its own
 * value.
 *
 * Disposing the fan-out disposes the slot's own sink when that sink has a
 * `Symbol.asyncDispose`, so boot's dispose reaches it as it would unwrapped.
 * The hooks are contributions and are not disposed.
 *
 * The fan-out is core's own and frozen, its disposable copy included, so a
 * write to the slot's value throws in strict-mode code. The sink it wraps is
 * the host's or the provider's and is not frozen, and without an
 * `auditHooks` contribution the slot holds that sink as it was given.
 *
 * A contributed hook with no `auditHooks` collector to read is a broken
 * invariant (the planner always merges it), refused rather than left a
 * fan-out to nothing.
 */
export function auditSlotFor(plan, contributionKinds, components) {
    if (!contributesAuditHooks(plan.validated.modules.map((m) => m.normalised)))
        return UNTOUCHED;
    const collector = contributionKinds?.auditHooks;
    if (collector === undefined) {
        throw new Error("invariant violated: auditHooks are contributed but stage 3 was handed no auditHooks collector");
    }
    const hooks = () => collector.values();
    const logger = () => components.logger;
    const fanOut = (sink) => {
        const own = sink === undefined || sink === null ? undefined : sink;
        const composite = createAuditFanOut({
            ...(own === undefined ? {} : { sink: own }),
            hooks,
            logger,
        });
        const dispose = own?.[Symbol.asyncDispose];
        if (typeof dispose !== "function")
            return composite;
        const disposable = Object.freeze({
            ...composite,
            [Symbol.asyncDispose]: async () => {
                await dispose.call(own);
            },
        });
        return disposable;
    };
    const provider = plan.providerActivations.some((activation) => activation.componentKey === "auditSink");
    return {
        beforeProviders() {
            // A host's sink is the map's own key; with neither it nor a provider,
            // the fan-out has the hooks alone.
            if (Object.hasOwn(components, "auditSink")) {
                components.auditSink = fanOut(components.auditSink);
            }
            else if (!provider) {
                components.auditSink = fanOut(undefined);
            }
        },
        provided(key, value) {
            return key === "auditSink" ? fanOut(value) : value;
        },
    };
}
export function auditHookRegistrations() {
    const modules = new Map();
    return {
        registered(value, module) {
            if (typeof value?.record !== "function") {
                throw new RangeError("auditHooks: the factory must answer an AuditSink, whose record is a function");
            }
            // The collector keeps one object once, under its first module.
            if (!modules.has(value))
                modules.set(value, module);
            return value;
        },
        log(components, collector) {
            const hooks = [...(collector?.values() ?? [])].map((hook, index) => ({
                sink: index + 1,
                module: modules.get(hook),
            }));
            if (hooks.length === 0)
                return;
            (components.logger ?? consoleLogger).info({ hooks }, "audit_hooks_registered");
        },
    };
}
