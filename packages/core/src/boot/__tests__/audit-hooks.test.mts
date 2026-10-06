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
 * `auditHooks` at boot: when a module contributes one, core fills the
 * `auditSink` slot with its fan-out over the slot's own sink and every hook,
 * so a reader of `deps.auditSink` reaches them all. Hooks alone satisfy the
 * slot's absence policy; with no sink and no hook the policy refuses boot as
 * before. The fan-out hands an event a hook records while it runs to the
 * slot's own sink alone, so a hook that reaches the slot cannot loop.
 */

import { describe, expect, it } from "vitest";
import { emitAuditEvent, recordAuditEvent } from "../../audit/factory.mjs";
import type { AuditEvent, AuditSink } from "../../audit/types.mjs";
import { AUDIT_SINK_ABSENCE_POLICY } from "../../audit/types.mjs";
import type { Logger } from "../../logging/Logger.mjs";
import { defineModule, type Module } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { auditHooksModule, createRecordingAuditSink } from "../../testing/index.mjs";
import { createApp, mergeWithBuiltins } from "../create-app.mjs";
import { materializeComponents } from "../materialize-components.mjs";
import { planBoot } from "../plan-boot.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";
import { validateManifests } from "../validate-manifests.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly auditFixtureNotifier: { notify(): void };
	}
}

const bootWith = (logger?: Logger): BootstrapMap =>
	({
		config: makeValidCoreConfig() as never,
		pathResolver: (s: string) => s,
		...(logger === undefined ? {} : { logger }),
	}) satisfies Record<string, unknown> as BootstrapMap;

/** A logger keeping each line's level, fields and message. */
const recordingLogger = () => {
	const lines: { level: string; fields: unknown; message: unknown }[] = [];
	const at = (level: string) => (fields: unknown, message?: unknown) => {
		lines.push({ level, fields, message });
	};
	const logger = {
		trace: () => {},
		debug: () => {},
		info: at("info"),
		warn: at("warn"),
		error: at("error"),
		fatal: () => {},
		child: () => logger,
	} as unknown as Logger;
	return { logger, lines };
};

async function refusal(promise: Promise<unknown>): Promise<BootError> {
	try {
		await promise;
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	return expect.fail("boot should have been refused");
}

const event: AuditEvent = { timestamp: new Date(0), type: "test.event" };

const sinkProvider = (sink: AuditSink): Module =>
	defineModule({
		name: "test:audit-sink",
		provides: { auditSink: () => sink },
	});

/** A reader of the slot, as every bundled emitter is, and the sink it was handed. */
function auditReader() {
	const handed: { sink?: AuditSink | undefined } = {};
	const module = defineModule({
		name: "test:audit-reader",
		optional: ["auditSink"],
		absencePolicies: { auditSink: AUDIT_SINK_ABSENCE_POLICY },
		contributes: {
			grantMiddleware: [
				(deps) => {
					handed.sink = deps.auditSink;
					return null;
				},
			],
		},
	});
	return { module, handed };
}

describe("auditHooks — fanned out through the auditSink slot", () => {
	it("hands an event a reader emits to the slot's sink and to every hook, in that order", async () => {
		const calls: string[] = [];
		const named = (name: string): AuditSink => ({
			kind: name,
			record: async () => {
				calls.push(name);
			},
		});
		const reader = auditReader();

		await createApp({
			modules: [
				sinkProvider(named("slot")),
				auditHooksModule("a", named("hook-a1"), named("hook-a2")),
				auditHooksModule("b", named("hook-b")),
				reader.module,
			],
			bootstrapComponents: bootWith(),
		});
		await recordAuditEvent(reader.handed.sink as AuditSink, event);

		expect(calls).toEqual(["slot", "hook-a1", "hook-a2", "hook-b"]);
	});

	it("fans out over the provider's sink, not one a polluted Object.prototype carries under the slot's name", async () => {
		const calls: string[] = [];
		const named = (name: string): AuditSink => ({
			kind: name,
			record: async () => {
				calls.push(name);
			},
		});
		const reader = auditReader();
		// Not enumerable, as a configuration parse would otherwise refuse it.
		Object.defineProperty(Object.prototype, "auditSink", {
			value: named("inherited"),
			configurable: true,
			writable: true,
		});
		try {
			await createApp({
				modules: [
					sinkProvider(named("slot")),
					auditHooksModule("a", named("hook-a")),
					reader.module,
				],
				bootstrapComponents: bootWith(),
			});
		} finally {
			delete (Object.prototype as Record<string, unknown>).auditSink;
		}
		await recordAuditEvent(reader.handed.sink as AuditSink, event);

		expect(calls).toEqual(["slot", "hook-a"]);
	});

	it("fans out to the hooks alone, with no provider, not to a sink a polluted Object.prototype carries", async () => {
		const calls: string[] = [];
		const named = (name: string): AuditSink => ({
			kind: name,
			record: async () => {
				calls.push(name);
			},
		});
		const reader = auditReader();
		// Not enumerable, as a configuration parse would otherwise refuse it.
		Object.defineProperty(Object.prototype, "auditSink", {
			value: named("inherited"),
			configurable: true,
			writable: true,
		});
		try {
			await createApp({
				modules: [auditHooksModule("a", named("hook-a")), reader.module],
				bootstrapComponents: bootWith(),
			});
		} finally {
			delete (Object.prototype as Record<string, unknown>).auditSink;
		}
		await recordAuditEvent(reader.handed.sink as AuditSink, event);

		expect(calls).toEqual(["hook-a"]);
	});

	it("fills the slot from the hooks alone, satisfying its absence policy", async () => {
		const hook = createRecordingAuditSink();
		const reader = auditReader();

		await createApp({
			modules: [auditHooksModule("test", hook), reader.module],
			bootstrapComponents: bootWith(),
		});
		await recordAuditEvent(reader.handed.sink as AuditSink, event);

		expect(hook.events.map((e) => e.type)).toEqual(["test.event"]);
	});

	it("fills the slot for a module that requires it from the hooks alone", async () => {
		const hook = createRecordingAuditSink();
		let handed: AuditSink | undefined;
		const requiring = defineModule({
			name: "test:audit-requirer",
			requires: ["auditSink"],
			contributes: {
				grantMiddleware: [
					(deps) => {
						handed = deps.auditSink;
						return null;
					},
				],
			},
		});

		await createApp({
			modules: [auditHooksModule("test", hook), requiring],
			bootstrapComponents: bootWith(),
		});
		await recordAuditEvent(handed as AuditSink, event);

		expect(hook.events).toHaveLength(1);
	});

	it("still refuses boot when nothing fills the slot and no module contributes a hook", async () => {
		const err = await refusal(
			createApp({ modules: [auditReader().module], bootstrapComponents: bootWith() }),
		);

		expect(err.reason).toBe("component-absence-undeclared");
	});

	it("hands a reader the slot's own sink when no module contributes a hook", async () => {
		const sink = createRecordingAuditSink();
		const reader = auditReader();

		await createApp({
			modules: [sinkProvider(sink), reader.module],
			bootstrapComponents: bootWith(),
		});

		expect(reader.handed.sink).toBe(sink);
	});

	it("fans out to an overriding sink and the hooks", async () => {
		const override = createRecordingAuditSink();
		const hook = createRecordingAuditSink();
		const reader = auditReader();

		await createApp({
			modules: [auditHooksModule("test", hook), reader.module],
			bootstrapComponents: bootWith(),
			overrideComponents: { auditSink: override },
		});
		await recordAuditEvent(reader.handed.sink as AuditSink, event);

		expect([override.events.length, hook.events.length]).toEqual([1, 1]);
	});

	it("still disposes the slot's own sink through Symbol.asyncDispose when hooks are contributed", async () => {
		let disposed = 0;
		const sink = Object.assign(createRecordingAuditSink(), {
			[Symbol.asyncDispose]: async () => {
				disposed++;
			},
		});

		const handle = await createApp({
			modules: [
				sinkProvider(sink),
				auditHooksModule("test", createRecordingAuditSink()),
				auditReader().module,
			],
			bootstrapComponents: bootWith(),
		});
		await handle.dispose();

		expect(disposed).toBe(1);
	});

	it("boots a module that reads auditSink and contributes a hook that never records into it", async () => {
		const hook = createRecordingAuditSink();
		let handed: AuditSink | undefined;
		const both = defineModule({
			name: "test:emits-and-hooks",
			optional: ["auditSink"],
			contributes: {
				auditHooks: [() => hook],
				grantMiddleware: [
					(deps) => {
						handed = deps.auditSink;
						return null;
					},
				],
			},
		});

		await createApp({ modules: [both], bootstrapComponents: bootWith() });
		await recordAuditEvent(handed as AuditSink, event);

		expect(hook.events).toHaveLength(1);
	});

	it("ends the loop of a hook that reaches the slot through another module's component", async () => {
		const adapter = createRecordingAuditSink();
		let hookCalls = 0;
		const notifier = defineModule({
			name: "test:notifier",
			optional: ["auditSink"],
			provides: {
				auditFixtureNotifier: (deps) => ({
					notify: () => {
						void emitAuditEvent(deps.auditSink, {
							timestamp: new Date(0),
							type: "test.notified",
						});
					},
				}),
			},
		});
		const notifyingHook = defineModule({
			name: "test:notifying-hook",
			requires: ["auditFixtureNotifier"],
			contributes: {
				auditHooks: [
					(deps) => ({
						kind: "notifying",
						record: async () => {
							hookCalls++;
							if (hookCalls < 20) deps.auditFixtureNotifier.notify();
						},
					}),
				],
			},
		});
		const reader = auditReader();

		await createApp({
			modules: [sinkProvider(adapter), notifier, notifyingHook, reader.module],
			bootstrapComponents: bootWith(recordingLogger().logger),
		});
		await recordAuditEvent(reader.handed.sink as AuditSink, event);
		await new Promise((resolve) => setTimeout(resolve, 20));

		expect({ hookCalls, adapter: adapter.events.map((e) => e.type) }).toEqual({
			hookCalls: 1,
			adapter: ["test.event", "test.notified"],
		});
	});

	it("refuses a host collector for auditHooks", async () => {
		const err = await refusal(
			createApp({
				modules: [auditHooksModule("test", createRecordingAuditSink())],
				bootstrapComponents: bootWith(),
				contributionKinds: { auditHooks: mergeWithBuiltins(undefined).auditHooks },
			}),
		);

		expect({ reason: err.reason, details: err.details }).toEqual({
			reason: "contribution-kind-guarded",
			details: { reason: "contribution-kind-guarded", kind: "auditHooks" },
		});
	});

	it("refuses a hook whose record is not a function, naming its module", async () => {
		const broken = defineModule({
			name: "test:broken-hook",
			contributes: { auditHooks: [() => ({ kind: "broken" }) as never] },
		});

		const err = await refusal(createApp({ modules: [broken], bootstrapComponents: bootWith() }));

		expect({ reason: err.reason, details: err.details }).toMatchObject({
			reason: "contribute-factory-failed",
			details: { module: "test:broken-hook", kind: "auditHooks" },
		});
	});

	it("says once at info which module contributed each hook, by the position audit_sink_failed names", async () => {
		const { logger, lines } = recordingLogger();

		await createApp({
			modules: [
				sinkProvider(createRecordingAuditSink()),
				auditHooksModule("a", createRecordingAuditSink(), createRecordingAuditSink()),
				auditHooksModule("b", createRecordingAuditSink()),
			],
			bootstrapComponents: bootWith(logger),
		});

		expect(lines.filter((line) => line.message === "audit_hooks_registered")).toEqual([
			{
				level: "info",
				message: "audit_hooks_registered",
				fields: {
					hooks: [
						{ sink: 1, module: "audit-hooks-a" },
						{ sink: 2, module: "audit-hooks-a" },
						{ sink: 3, module: "audit-hooks-b" },
					],
				},
			},
		]);
	});

	it("refuses to fill the slot without the collectors when a hook is contributed (an invariant)", async () => {
		const modules = [auditHooksModule("test", createRecordingAuditSink())];
		const bootstrap = bootWith();
		const validated = validateManifests({
			modules,
			bootstrapComponents: bootstrap,
			contributionKinds: mergeWithBuiltins(undefined),
		});
		const plan = planBoot(validated, validated.bootstrapComponents, undefined);

		await expect(
			materializeComponents(plan, validated.bootstrapComponents, undefined),
		).rejects.toThrow(/invariant violated/);
		await expect(
			materializeComponents(plan, validated.bootstrapComponents, undefined, {}),
		).rejects.toThrow(/invariant violated/);
	});
});

describe("auditHooks — the composed sink is frozen", () => {
	/** Whether `sink` is frozen and refuses a write to `record` with a TypeError. */
	const refusesWrites = (sink: AuditSink | undefined): void => {
		expect(Object.isFrozen(sink)).toBe(true);
		expect(() => {
			(sink as { record: unknown }).record = async () => {};
		}).toThrow(TypeError);
	};

	it("holds a frozen fan-out over the hooks alone, the one a reader is handed", async () => {
		const reader = auditReader();

		const handle = await createApp({
			modules: [auditHooksModule("test", createRecordingAuditSink()), reader.module],
			bootstrapComponents: bootWith(),
		});

		expect(reader.handed.sink).toBe(handle.components.auditSink);
		refusesWrites(handle.components.auditSink);
	});

	it("holds a frozen fan-out over a provider's sink with Symbol.asyncDispose, the provider's own sink left unfrozen", async () => {
		const sink = Object.assign(createRecordingAuditSink(), {
			[Symbol.asyncDispose]: async () => {},
		});
		const reader = auditReader();

		const handle = await createApp({
			modules: [
				sinkProvider(sink),
				auditHooksModule("test", createRecordingAuditSink()),
				reader.module,
			],
			bootstrapComponents: bootWith(),
		});

		expect(reader.handed.sink).toBe(handle.components.auditSink);
		expect(
			typeof (handle.components.auditSink as Partial<AsyncDisposable>)[Symbol.asyncDispose],
		).toBe("function");
		refusesWrites(handle.components.auditSink);
		expect(Object.isFrozen(sink)).toBe(false);
	});

	it("holds a frozen fan-out over a host's sink, the host's own sink left unfrozen", async () => {
		const sink = createRecordingAuditSink();

		const handle = await createApp({
			modules: [auditHooksModule("test", createRecordingAuditSink()), auditReader().module],
			bootstrapComponents: { ...bootWith(), auditSink: sink } as BootstrapMap,
		});

		refusesWrites(handle.components.auditSink);
		expect(Object.isFrozen(sink)).toBe(false);
	});

	it("hands a provider's sink through as it is, unfrozen, when no module contributes a hook", async () => {
		const sink = createRecordingAuditSink();

		const handle = await createApp({
			modules: [sinkProvider(sink), auditReader().module],
			bootstrapComponents: bootWith(),
		});

		expect(handle.components.auditSink).toBe(sink);
		expect(Object.isFrozen(sink)).toBe(false);
	});
});
