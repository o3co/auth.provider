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
 * The declared-absence guard: a module attaches an `absencePolicies` entry to
 * an optional key, and stage 1 refuses boot when the slot is unfilled and the
 * config does not carry the policy's declared-absent value. Absence of such a
 * capability has to be declared; it is never a silent no-op.
 *
 * `auditSink` is the test subject: the bundled modules that read it declare
 * `AUDIT_SINK_ABSENCE_POLICY`, so a composition without a sink must list
 * `auditSink` in `core.declaredAbsent` out loud.
 */
import { describe, expect, it } from "vitest";
import {
	AUDIT_SINK_ABSENCE_POLICY,
	createApp,
	defineModule,
	describeAbsenceDeclaration,
	isAbsenceDeclared,
	memoryRateLimiterModule,
	RATE_LIMITER_ABSENCE_POLICY,
} from "../../index.mjs";
import { coreConfigForTests, makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
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

/** `core` declaring `names` absent. */
const declaring = (...names: string[]) => coreConfigForTests({ declaredAbsent: names });

/**
 * `makeValidAppConfig` deliberately declares the audit sink absent so
 * ordinary module tests boot without a sink; the fixture for THIS suite
 * strips that declaration, because the undeclared state is the subject.
 */
function boot(configOverrides: Record<string, unknown> = {}) {
	const { audit: _audit, ...config } = makeValidAppConfig() as Record<string, unknown> & {
		audit?: unknown;
	};
	return {
		config: { ...config, ...coreConfigForTests(), ...configOverrides },
		pathResolver: (p: string) => p,
	} as never;
}

describe("checkDeclaredAbsence", () => {
	it("fails boot when the slot is unfilled and its absence is undeclared", async () => {
		await expect(
			createApp({ modules: [auditConsumerModule], bootstrapComponents: boot() }),
		).rejects.toMatchObject({
			reason: "component-absence-undeclared",
			details: {
				reason: "component-absence-undeclared",
				componentKey: "auditSink",
				consumedBy: ["test:audit-consumer"],
				configKey: "core.declaredAbsent",
				absentValue: "auditSink",
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
		expect(message).toContain('list "auditSink" in core.declaredAbsent');
		expect(message).toContain(AUDIT_SINK_ABSENCE_POLICY.hint);
	});

	it("boots when core.declaredAbsent lists the slot", async () => {
		await expect(
			createApp({
				modules: [auditConsumerModule],
				bootstrapComponents: boot(declaring("auditSink")),
			}),
		).resolves.toBeDefined();
	});

	it("declares nothing through a list naming other slots", async () => {
		await expect(
			createApp({
				modules: [auditConsumerModule],
				bootstrapComponents: boot(declaring("mailSender")),
			}),
		).rejects.toMatchObject({ reason: "component-absence-undeclared" });
	});

	it('declares nothing through audit.sink.type = "none", where the declaration was', async () => {
		await expect(
			createApp({
				modules: [auditConsumerModule],
				bootstrapComponents: boot({ audit: { sink: { type: "none" } } }),
			}),
		).rejects.toMatchObject({ reason: "component-absence-undeclared" });
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
			bootstrapComponents: boot(declaring("auditSink")),
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

/** A module that reads `rateLimiter` and attaches no policy of its own. */
const limiterReaderModule = defineModule({
	name: "test:limiter-reader",
	optional: ["rateLimiter"] as const,
});

/** A second reader of the slot. */
const secondLimiterReaderModule = defineModule({
	name: "test:limiter-reader-2",
	optional: ["rateLimiter"] as const,
});

describe("checkDeclaredAbsence — the rateLimiter slot, whose policy core attaches", () => {
	it("refuses boot when no limiter is wired and the absence is undeclared, naming the slot and the fix", async () => {
		const err = await createApp({
			modules: [limiterReaderModule, secondLimiterReaderModule],
			bootstrapComponents: boot(),
		}).catch((e: unknown) => e as BootError);
		expect(err).toBeInstanceOf(BootError);
		expect(err).toMatchObject({
			reason: "component-absence-undeclared",
			details: {
				reason: "component-absence-undeclared",
				componentKey: "rateLimiter",
				consumedBy: ["test:limiter-reader", "test:limiter-reader-2"],
				configKey: "core.declaredAbsent",
				absentValue: "rateLimiter",
			},
		});
		expect((err as BootError).message).toContain('list "rateLimiter" in core.declaredAbsent');
		expect((err as BootError).message).toContain(RATE_LIMITER_ABSENCE_POLICY.hint);
	});

	it("boots with no limiter when core.declaredAbsent lists the slot, and leaves it empty", async () => {
		const handle = await createApp({
			modules: [limiterReaderModule],
			bootstrapComponents: boot(declaring("rateLimiter")),
		});
		expect(handle.components.rateLimiter).toBeUndefined();
		await handle.dispose();
	});

	it("boots with a limiter wired, with no declaration needed", async () => {
		const handle = await createApp({
			modules: [limiterReaderModule, memoryRateLimiterModule],
			bootstrapComponents: boot(),
		});
		await handle.dispose();
	});

	it("asks nothing of a composition in which no module reads the slot", async () => {
		const handle = await createApp({ modules: [], bootstrapComponents: boot() });
		await handle.dispose();
	});

	it("agrees with a module attaching the same policy, and refuses one that differs", async () => {
		const attaching = defineModule({
			name: "test:limiter-reader-attaching",
			optional: ["rateLimiter"] as const,
			absencePolicies: { rateLimiter: RATE_LIMITER_ABSENCE_POLICY },
		});
		const agreeing = await createApp({
			modules: [limiterReaderModule, attaching],
			bootstrapComponents: boot(declaring("rateLimiter")),
		});
		await agreeing.dispose();

		const differing = defineModule({
			name: "test:limiter-reader-differing",
			optional: ["rateLimiter"] as const,
			absencePolicies: {
				rateLimiter: { ...RATE_LIMITER_ABSENCE_POLICY, hint: "a different story" },
			},
		});
		const err = await createApp({
			modules: [limiterReaderModule, differing],
			bootstrapComponents: boot(declaring("rateLimiter")),
		}).catch((e: unknown) => e as BootError);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).message).toContain("disagree");
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
			bootstrapComponents: boot(declaring("auditSink")),
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
			bootstrapComponents: boot(declaring("auditSink")),
		}).catch((e: unknown) => e as BootError);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).message).toContain("disagree");
	});
});

describe("isAbsenceDeclared and describeAbsenceDeclaration — one reading of a declaration", () => {
	it("reads a list key as declaring the absent value when the list holds it", () => {
		expect(isAbsenceDeclared(declaring("auditSink"), AUDIT_SINK_ABSENCE_POLICY)).toBe(true);
		expect(isAbsenceDeclared(declaring("mailSender"), AUDIT_SINK_ABSENCE_POLICY)).toBe(false);
		expect(isAbsenceDeclared({}, AUDIT_SINK_ABSENCE_POLICY)).toBe(false);
	});

	it("reads a scalar key as declaring it when it holds the absent value", () => {
		const policy = {
			configKey: ["oauth", "revocation", "subject"],
			absentValue: "unsupported",
			hint: "h",
		};
		expect(isAbsenceDeclared({ oauth: { revocation: { subject: "unsupported" } } }, policy)).toBe(
			true,
		);
		expect(isAbsenceDeclared({ oauth: { revocation: { subject: "watermark" } } }, policy)).toBe(
			false,
		);
	});

	it("reads a list at a key other than core's list as no declaration", () => {
		const policy = {
			configKey: ["oauth", "revocation", "subject"],
			absentValue: "unsupported",
			hint: "h",
		};
		expect(isAbsenceDeclared({ oauth: { revocation: { subject: ["unsupported"] } } }, policy)).toBe(
			false,
		);
	});

	it("reads own keys only", () => {
		expect(
			isAbsenceDeclared(
				Object.create({ core: { declaredAbsent: ["auditSink"] } }),
				AUDIT_SINK_ABSENCE_POLICY,
			),
		).toBe(false);
	});

	it("says how to declare the absence, for a list key and for a scalar one", () => {
		expect(describeAbsenceDeclaration(AUDIT_SINK_ABSENCE_POLICY)).toBe(
			'list "auditSink" in core.declaredAbsent',
		);
		expect(
			describeAbsenceDeclaration({
				configKey: ["oauth", "revocation", "subject"],
				absentValue: "unsupported",
				hint: "h",
			}),
		).toBe('set oauth.revocation.subject = "unsupported"');
	});
});
