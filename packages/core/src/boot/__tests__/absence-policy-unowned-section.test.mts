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
 * A declared-absence policy whose key lies in a section core does not own:
 * `SUBJECT_REVOCATION_ABSENCE_POLICY` and `ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY`
 * read `oauth.revocation.*`, which is the oauth module's section, while
 * modules outside the oauth package attach them too. With no oauth-package
 * module loaded, nothing layers the oauth package's `reference.conf`, so
 * `OAUTH_REVOCATION_SUBJECT` and `OAUTH_REVOCATION_ACCESS_TOKEN` bind nothing
 * — core's own `reference.conf` sets no `oauth {}` — and the guard refuses the
 * unfilled slot (fail-closed) where a deployment relying on the variable
 * would once have booted. A value written at the key is read as written.
 *
 * The section the guard reads is owned while a loaded module's policy reads
 * it: boot does not name it among the sections nothing loaded reads.
 */

import { fileURLToPath } from "node:url";
import { parseFile, parseString } from "@o3co/ts.hocon";
import { describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY } from "#/access-token-denylist/types.mjs";
import { createApp } from "#/boot/create-app.mjs";
import { BootError } from "#/boot/types.mjs";
import { coreReference } from "#/config/references.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { SUBJECT_REVOCATION_ABSENCE_POLICY } from "#/user-sessions/types.mjs";

/** Reads the watermark slot, and refuses to be silently without it. */
const watermarkConsumer = defineModule({
	name: "test:watermark-consumer",
	optional: ["subjectRevocation"] as const,
	absencePolicies: { subjectRevocation: SUBJECT_REVOCATION_ABSENCE_POLICY },
});

/** Reads the access-token denylist slot, and refuses to be silently without it. */
const denylistConsumer = defineModule({
	name: "test:denylist-consumer",
	optional: ["accessTokenDenylist"] as const,
	absencePolicies: { accessTokenDenylist: ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY },
});

/** A logger whose every method is a spy. */
function recordingLogger(): Logger & { readonly warn: ReturnType<typeof vi.fn> } {
	return {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
	} as unknown as Logger & { readonly warn: ReturnType<typeof vi.fn> };
}

/** The notices of `name` the boot logged at warn, each call's fields. */
const noticesOf = (logger: ReturnType<typeof recordingLogger>, name: string): unknown[] =>
	logger.warn.mock.calls.filter(([, message]) => message === name).map(([fields]) => fields);

/**
 * Core's valid configuration with no `oauth {}` and none of the oauth
 * package's sections, and whatever `operator` HOCON over core's own
 * `reference.conf`, both resolved under `env`, sets at `oauth`: what a
 * composition loading no oauth-package module resolves there.
 */
function resolvedWithoutOAuth(env: Record<string, string>, operator = ""): Record<string, unknown> {
	const {
		oauth: _oauth,
		"oauth-session": _session,
		"oauth-authorization": _authorization,
		...fixture
	} = makeValidCoreConfig() as Record<string, unknown>;
	const layered = parseString(operator, { env })
		.withFallback(parseFile(fileURLToPath(coreReference()), { env }))
		.toObject() as Record<string, unknown>;
	return { ...fixture, ...(layered.oauth === undefined ? {} : { oauth: layered.oauth }) };
}

const bootOn = (config: Record<string, unknown>, modules = [watermarkConsumer], logger?: Logger) =>
	createApp({
		modules,
		bootstrapComponents: {
			config,
			pathResolver: (p: string) => p,
			...(logger === undefined ? {} : { logger }),
		} as never,
	});

describe("an absence policy keyed in oauth {} with no oauth-package module loaded", () => {
	it("core's reference.conf sets no oauth {}, so the revocation variables bind nothing", () => {
		const resolved = resolvedWithoutOAuth({
			OAUTH_REVOCATION_SUBJECT: "unsupported",
			OAUTH_REVOCATION_ACCESS_TOKEN: "unsupported",
		});
		expect(resolved.oauth).toBeUndefined();
	});

	it("refuses an unfilled subjectRevocation although OAUTH_REVOCATION_SUBJECT is exported", async () => {
		const err = await bootOn(
			resolvedWithoutOAuth({ OAUTH_REVOCATION_SUBJECT: "unsupported" }),
		).then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(BootError);
		expect(err).toMatchObject({
			reason: "component-absence-undeclared",
			details: {
				componentKey: "subjectRevocation",
				configKey: "oauth.revocation.subject",
				absentValue: "unsupported",
			},
		});
	});

	it("refuses an unfilled accessTokenDenylist although OAUTH_REVOCATION_ACCESS_TOKEN is exported", async () => {
		await expect(
			bootOn(resolvedWithoutOAuth({ OAUTH_REVOCATION_ACCESS_TOKEN: "unsupported" }), [
				denylistConsumer,
			]),
		).rejects.toMatchObject({
			reason: "component-absence-undeclared",
			details: {
				componentKey: "accessTokenDenylist",
				configKey: "oauth.revocation.accessToken",
			},
		});
	});

	it("reads a value written at the key as written, and boots", async () => {
		const handle = await bootOn(
			resolvedWithoutOAuth(
				{},
				'oauth.revocation.subject = "unsupported"\noauth.revocation.accessToken = "unsupported"\n',
			),
			[watermarkConsumer, denylistConsumer],
		);
		await handle.dispose();
	});

	it("refuses any written value but the declaration itself", async () => {
		for (const written of ['"Unsupported"', '" unsupported"', '"watermark"', "true"]) {
			await expect(
				bootOn(resolvedWithoutOAuth({}, `oauth.revocation.subject = ${written}\n`)),
			).rejects.toMatchObject({ reason: "component-absence-undeclared" });
		}
	});

	it("does not name oauth as a section nothing loaded reads while a loaded policy reads it", async () => {
		const logger = recordingLogger();
		const handle = await bootOn(
			resolvedWithoutOAuth({}, 'oauth.revocation.subject = "unsupported"\n'),
			[watermarkConsumer],
			logger,
		);
		await handle.dispose();
		expect(noticesOf(logger, "config_sections_ignored")).toEqual([]);
		expect(noticesOf(logger, "config_sections_not_loaded")).toEqual([]);
	});

	it("names oauth as ignored when no loaded module reads it", async () => {
		const logger = recordingLogger();
		const handle = await bootOn(
			resolvedWithoutOAuth({}, 'oauth.revocation.subject = "unsupported"\n'),
			[],
			logger,
		);
		await handle.dispose();
		expect(noticesOf(logger, "config_sections_ignored")).toEqual([{ sections: ["oauth"] }]);
	});
});
