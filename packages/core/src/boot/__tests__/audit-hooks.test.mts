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
 * before. A module that contributes a hook may not read `auditSink`.
 */

import { describe, expect, it } from "vitest";
import { recordAuditEvent } from "../../audit/factory.mjs";
import type { AuditEvent, AuditSink } from "../../audit/types.mjs";
import { AUDIT_SINK_ABSENCE_POLICY } from "../../audit/types.mjs";
import { defineModule, type Module } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { auditHooksModule, createRecordingAuditSink } from "../../testing/index.mjs";
import { createApp } from "../create-app.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

const bootWith = (extra: Record<string, unknown> = {}): BootstrapMap =>
	({
		config: { ...makeValidCoreConfig(), ...extra } as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

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

	it("refuses a module that contributes a hook and reads auditSink", async () => {
		const loop = defineModule({
			name: "test:hook-reading-the-slot",
			optional: ["auditSink"],
			contributes: { auditHooks: [() => createRecordingAuditSink()] },
		});

		const err = await refusal(
			createApp({
				modules: [loop],
				bootstrapComponents: bootWith(),
			}),
		);

		expect({ reason: err.reason, stage: err.stage, details: err.details }).toEqual({
			reason: "circular-dependency",
			stage: "validateManifests",
			details: {
				reason: "circular-dependency",
				cycle: [
					{
						module: "test:hook-reading-the-slot",
						requires: "auditSink",
						satisfiedBy: "test:hook-reading-the-slot",
					},
				],
			},
		});
	});
});
