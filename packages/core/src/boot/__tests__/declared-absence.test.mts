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
 * The declared-absence guard (#363).
 *
 * An `optional` manifest key used to mean "absence is indistinguishable from
 * nothing-to-do", and three shipped silent no-ops came from exactly that:
 * revocation with no denylist (#277), a subject-revocation watermark nothing
 * read (#322), and an unwired audit sink discarding every security event
 * (#287). #277 hand-rolled the answer — refuse boot unless the capability is
 * declared absent in config — as a key-specific check. `absencePolicies`
 * makes that answer a manifest vocabulary: a module attaches a policy to an
 * optional key, and stage 1 refuses boot when the slot is unfilled and the
 * config does not carry the policy's declared-absent value.
 *
 * `auditSink` is both the first real policy and the test subject here: the
 * three bundled modules that read it declare `AUDIT_SINK_ABSENCE_POLICY`, so
 * a composition without a sink must say `audit.sink.type = "none"` out loud.
 */
import { describe, expect, it } from "vitest";
import { AUDIT_SINK_ABSENCE_POLICY, createApp, defineModule } from "../../index.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

/** A module that reads `auditSink` and refuses to be silently sink-less. */
const auditConsumerModule = defineModule({
	name: "test:audit-consumer",
	optional: ["auditSink"] as const,
	absencePolicies: { auditSink: AUDIT_SINK_ABSENCE_POLICY },
});

/** A second consumer carrying the SAME policy — consumedBy must list both. */
const secondAuditConsumerModule = defineModule({
	name: "test:audit-consumer-2",
	optional: ["auditSink"] as const,
	absencePolicies: { auditSink: AUDIT_SINK_ABSENCE_POLICY },
});

/** A consumer whose policy disagrees with the shared one — a manifest bug. */
const conflictingConsumerModule = defineModule({
	name: "test:audit-consumer-conflict",
	optional: ["auditSink"] as const,
	absencePolicies: {
		auditSink: {
			configKey: ["audit", "sink", "type"],
			absentValue: "off",
			hint: "a dialect nothing else speaks",
		},
	},
});

const auditProviderModule = defineModule({
	name: "test:audit-provider",
	provides: {
		auditSink: () => ({ kind: "stub", record: async () => {} }),
	} as never,
});

/**
 * `makeValidAppConfig` deliberately carries `audit.sink.type = "none"` (#363)
 * so ordinary module tests boot without a sink; the fixture for THIS suite
 * strips that declaration, because the undeclared state is the subject.
 */
function boot(configOverrides: Record<string, unknown> = {}) {
	const { audit, ...withoutDeclaration } = makeValidAppConfig() as Record<string, unknown> & {
		audit?: unknown;
	};
	void audit;
	return {
		config: { ...withoutDeclaration, ...configOverrides },
		pathResolver: (p: string) => p,
	} as never;
}

describe("checkDeclaredAbsence (#363)", () => {
	it("fails boot when the slot is unfilled and its absence is undeclared", async () => {
		await expect(
			createApp({ modules: [auditConsumerModule], bootstrapComponents: boot() }),
		).rejects.toMatchObject({
			reason: "component-absence-undeclared",
			details: {
				reason: "component-absence-undeclared",
				componentKey: "auditSink",
				consumedBy: ["test:audit-consumer"],
				configKey: "audit.sink.type",
				absentValue: "none",
			},
		});
	});

	it("names both ways out in the message, hint included", async () => {
		const err = await createApp({
			modules: [auditConsumerModule],
			bootstrapComponents: boot(),
		}).catch((e: unknown) => e as BootError);
		expect(err).toBeInstanceOf(BootError);
		const message = (err as BootError).message;
		expect(message).toContain("auditSink");
		expect(message).toContain('audit.sink.type = "none"');
		expect(message).toContain(AUDIT_SINK_ABSENCE_POLICY.hint);
	});

	it("boots when the config declares the capability absent", async () => {
		await expect(
			createApp({
				modules: [auditConsumerModule],
				bootstrapComponents: boot({ audit: { sink: { type: "none" } } }),
			}),
		).resolves.toBeDefined();
	});

	it("boots when a module provides the slot, with no declaration needed", async () => {
		await expect(
			createApp({
				modules: [auditConsumerModule, auditProviderModule],
				bootstrapComponents: boot(),
			}),
		).resolves.toBeDefined();
	});

	it("boots when the slot arrives through bootstrapComponents", async () => {
		const bootstrap = {
			...(boot() as Record<string, unknown>),
			auditSink: { kind: "stub", record: async () => {} },
		} as never;
		await expect(
			createApp({ modules: [auditConsumerModule], bootstrapComponents: bootstrap }),
		).resolves.toBeDefined();
	});

	it("lists every module reading the slot as the evidence", async () => {
		await expect(
			createApp({
				modules: [auditConsumerModule, secondAuditConsumerModule],
				bootstrapComponents: boot(),
			}),
		).rejects.toMatchObject({
			details: {
				reason: "component-absence-undeclared",
				consumedBy: ["test:audit-consumer", "test:audit-consumer-2"],
			},
		});
	});

	it("refuses two modules whose policies for one key disagree", async () => {
		// Deliberately louder than first-wins: a composition where two modules
		// hand the operator different declarations for the same capability
		// would make the boot error's advice depend on module order.
		const err = await createApp({
			modules: [auditConsumerModule, conflictingConsumerModule],
			bootstrapComponents: boot({ audit: { sink: { type: "none" } } }),
		}).catch((e: unknown) => e as BootError);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("component-absence-undeclared");
		expect((err as BootError).message).toContain("test:audit-consumer");
		expect((err as BootError).message).toContain("test:audit-consumer-conflict");
		expect((err as BootError).message).toContain("disagree");
	});

	it("does not fire for an optional key with no policy", async () => {
		const plainOptionalModule = defineModule({
			name: "test:plain-optional",
			optional: ["auditSink"] as const,
		});
		await expect(
			createApp({ modules: [plainOptionalModule], bootstrapComponents: boot() }),
		).resolves.toBeDefined();
	});
});

describe("checkDeclaredAbsence — manifest authoring bugs", () => {
	it("refuses a policy on a key the module does not list in requires/optional", async () => {
		// `defineModule`'s `const O` inference lets `absencePolicies` widen `O`
		// on its own, so this compiles — which is exactly why the guard has to
		// catch it at stage 1 instead of the type system.
		const policyWithoutRead = defineModule({
			name: "test:policy-without-read",
			absencePolicies: { auditSink: AUDIT_SINK_ABSENCE_POLICY },
		});
		const err = await createApp({
			modules: [policyWithoutRead],
			bootstrapComponents: boot({ audit: { sink: { type: "none" } } }),
		}).catch((e: unknown) => e as BootError);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("component-absence-undeclared");
		expect((err as BootError).message).toContain("does not list it in requires or optional");
	});

	it("refuses two policies that differ only in hint", async () => {
		// The hint is interpolated into the boot error, so a hint-only
		// difference still makes the operator-facing advice order-dependent.
		const hintVariantModule = defineModule({
			name: "test:audit-consumer-hint-variant",
			optional: ["auditSink"] as const,
			absencePolicies: {
				auditSink: { ...AUDIT_SINK_ABSENCE_POLICY, hint: "a different story" },
			},
		});
		const err = await createApp({
			modules: [auditConsumerModule, hintVariantModule],
			bootstrapComponents: boot({ audit: { sink: { type: "none" } } }),
		}).catch((e: unknown) => e as BootError);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).message).toContain("disagree");
	});
});
