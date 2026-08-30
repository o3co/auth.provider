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
 * Issue #406 — the one silent no-op #363 did not close.
 *
 * #363 introduced `ModuleSpec.absencePolicies` so an unfilled optional slot
 * has to be a *stated* decision at boot, and its own doc cites "a
 * subject-revocation watermark nothing consulted (#322)" as a motivating
 * example. `auditSink` and `accessTokenDenylist` got policies.
 * `subjectRevocation` and `subjectSessionIndex` did not.
 *
 * The consequence, in every shape this repository shipped: a scaffolded
 * deployment got `subjectRevocation: undefined`, so `verifyJwt` skipped the
 * watermark check, the #376 refresh-redemption gate was inert, and
 * `revokeAllForSubject` reported `unavailable` — with no boot-time signal in
 * either direction. Exactly the shape `absencePolicies` exists to refuse.
 *
 * One config key covers both slots. They are two components but one
 * capability: subject-level revocation needs the index to enumerate what to
 * cascade and the watermark to refuse what the cascade missed, and a
 * deployment that has neither has one thing to say, not two. #321's adapters
 * fill them together for the same reason.
 */

import { describe, expect, it } from "vitest";
import type { BootError } from "../../boot/types.mjs";
import { createApp, defineModule, SUBJECT_REVOCATION_ABSENCE_POLICY } from "../../index.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";

const watermarkConsumer = defineModule({
	name: "test:watermark-consumer",
	optional: ["subjectRevocation"] as const,
	absencePolicies: { subjectRevocation: SUBJECT_REVOCATION_ABSENCE_POLICY },
});

const indexConsumer = defineModule({
	name: "test:index-consumer",
	optional: ["subjectSessionIndex"] as const,
	absencePolicies: { subjectSessionIndex: SUBJECT_REVOCATION_ABSENCE_POLICY },
});

const watermarkProvider = defineModule({
	name: "test:watermark-provider",
	provides: {
		subjectRevocation: () => ({
			kind: "stub",
			revokeBefore: async () => {},
			revokedBefore: async () => null,
		}),
	} as never,
});

const indexProvider = defineModule({
	name: "test:index-provider",
	provides: {
		subjectSessionIndex: () => ({
			kind: "stub",
			addSid: async () => {},
			listSids: async () => [],
			removeSid: async () => {},
			removeBySubject: async () => {},
		}),
	} as never,
});

/**
 * The valid fixture with `oauth.revocation.subject` set to `value`, or removed
 * entirely when `value` is undefined — the undeclared state is the subject of
 * most of these cases.
 *
 * `oauth.revocation` is only rewritten when the fixture already carries it:
 * the schema requires `accessToken` inside that object, so materialising an
 * empty one would fail config validation before the guard under test runs.
 */
function boot(value?: "watermark" | "unsupported") {
	const base = makeValidAppConfig() as Record<string, unknown> & {
		oauth?: Record<string, unknown>;
	};
	const oauth = { ...(base.oauth ?? {}) } as Record<string, unknown>;
	const revocation = oauth.revocation as Record<string, unknown> | undefined;
	if (value === undefined) {
		if (revocation !== undefined) {
			const { subject, ...rest } = revocation;
			void subject;
			oauth.revocation = rest;
		}
	} else {
		// `accessToken` is required once the `revocation` object exists (#277),
		// and the fixture carries no `revocation` at all — so a config that
		// declares only `subject` has to restate it. A real deployment inherits
		// it from reference.conf and writes one line.
		oauth.revocation = { accessToken: "denylist", ...(revocation ?? {}), subject: value };
	}
	return { config: { ...base, oauth }, pathResolver: (p: string) => p } as never;
}

/** `boot()` plus `oauth.revocation.subject = <value>`. */
const bootDeclaring = (value: "watermark" | "unsupported") => boot(value);

describe("SUBJECT_REVOCATION_ABSENCE_POLICY (#406)", () => {
	it("refuses boot when the watermark slot is unfilled and undeclared", async () => {
		await expect(
			createApp({ modules: [watermarkConsumer], bootstrapComponents: boot() }),
		).rejects.toMatchObject({
			reason: "component-absence-undeclared",
			details: {
				componentKey: "subjectRevocation",
				configKey: "oauth.revocation.subject",
				absentValue: "unsupported",
			},
		});
	});

	it("refuses boot when the session index is unfilled and undeclared", async () => {
		await expect(
			createApp({ modules: [indexConsumer], bootstrapComponents: boot() }),
		).rejects.toMatchObject({
			reason: "component-absence-undeclared",
			details: { componentKey: "subjectSessionIndex" },
		});
	});

	it("names what goes silent, not just that something is missing", async () => {
		// The hint is the whole value of the policy: an operator who reads
		// "subjectRevocation is unfilled" learns nothing about what stopped
		// working.
		const err = (await createApp({
			modules: [watermarkConsumer],
			bootstrapComponents: boot(),
		}).catch((e: unknown) => e)) as BootError;
		expect(err.message).toContain("oauth.revocation.subject");
		expect(err.message).toMatch(/password|credential/i);
	});

	it("boots once the deployment declares the capability absent", async () => {
		await expect(
			createApp({
				modules: [watermarkConsumer, indexConsumer],
				bootstrapComponents: bootDeclaring("unsupported"),
			}),
		).resolves.toBeDefined();
	});

	it("boots when both slots are filled, with no declaration needed", async () => {
		await expect(
			createApp({
				modules: [watermarkConsumer, indexConsumer, watermarkProvider, indexProvider],
				bootstrapComponents: boot(),
			}),
		).resolves.toBeDefined();
	});

	it("uses one key for both slots — one capability, one decision", async () => {
		// Two components, but a deployment that has neither has one thing to
		// say. #321's adapters fill them together for the same reason.
		expect(SUBJECT_REVOCATION_ABSENCE_POLICY.configKey).toEqual(["oauth", "revocation", "subject"]);
		expect(SUBJECT_REVOCATION_ABSENCE_POLICY.absentValue).toBe("unsupported");
	});
});
