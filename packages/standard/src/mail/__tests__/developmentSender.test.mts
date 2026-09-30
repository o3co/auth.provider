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
 * The development mail sender: it delivers nothing and logs, at info, the
 * purpose and the code of each send, nothing else of it. Its module fills
 * the `mailSender` slot, declares no section, and is installed only where
 * the configuration was selected as development or test — an allow-list —
 * and never where that name, `CONFIG_ENV` or `NODE_ENV` says production or
 * staging, or on a multi-replica deployment.
 */

import {
	BootError,
	createApp,
	type DeploymentMode,
	type Logger,
	type MailSend,
	type MailSender,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { afterEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import {
	type StandardDevelopmentMailSenderModuleOptions,
	standardDevelopmentMailSenderModule,
} from "#/mail/development/module.mjs";
import { createStandardDevelopmentMailSender } from "#/mail/development/sender.mjs";

const SEND: MailSend = {
	purpose: "account_email_proof",
	subject: "u-alice",
	to: "alice@example.com",
	code: "7K3M-9QX2-HD4P-WN8R",
	expiresAtMs: Date.UTC(2026, 8, 30, 12, 10),
};

/** Every call a logger was handed: its level, and what it was handed. */
function recordingLogger(): { readonly logger: Logger; readonly calls: unknown[][] } {
	const calls: unknown[][] = [];
	const at =
		(level: string) =>
		(...args: unknown[]) => {
			calls.push([level, ...args]);
		};
	const logger: Logger = {
		trace: at("trace"),
		debug: at("debug"),
		info: at("info"),
		warn: at("warn"),
		error: at("error"),
		fatal: at("fatal"),
		child: () => logger,
	};
	return { logger, calls };
}

/** The module's `mailSender` factory, called with the slots it reads; a refusal is a rejection. */
const provide = async (
	options: StandardDevelopmentMailSenderModuleOptions,
	deploymentMode: DeploymentMode,
	logger?: Logger,
): Promise<MailSender> =>
	(
		standardDevelopmentMailSenderModule(options).provides as {
			mailSender: (deps: unknown) => MailSender | Promise<MailSender>;
		}
	).mailSender({ deploymentMode, logger });

describe("createStandardDevelopmentMailSender", () => {
	it("logs one line at info per send, the purpose and the code and nothing else of the mail, and answers delivered", async () => {
		const { logger, calls } = recordingLogger();
		const sender = createStandardDevelopmentMailSender({ logger });
		expect(sender.kind).toBe("standard-development");
		expect(await sender.send(SEND)).toEqual({ outcome: "delivered" });
		expect(calls).toEqual([
			["info", { purpose: "account_email_proof", code: "7K3M-9QX2-HD4P-WN8R" }, "mail_code_issued"],
		]);
		const written = JSON.stringify(calls);
		for (const part of ["alice", "u-alice", String(SEND.expiresAtMs)]) {
			expect(written, part).not.toContain(part);
		}
	});

	it("leaves the mail it is handed as it was", async () => {
		const mail = Object.freeze({ ...SEND });
		await createStandardDevelopmentMailSender({ logger: recordingLogger().logger }).send(mail);
		expect(mail).toEqual(SEND);
	});
});

describe("standardDevelopmentMailSenderModule", () => {
	afterEach(() => {
		vi.unstubAllEnvs();
	});

	it("is named after itself, fills the mailSender slot at every boot from the deployment mode and the logger, and declares no section", () => {
		const module = standardDevelopmentMailSenderModule({ environment: "development" });
		expect(module.name).toBe("standard-development-mail-sender");
		expect(Object.keys(module.provides ?? {})).toEqual(["mailSender"]);
		expect(module.lifecycle?.mailSender?.eager).toBe(true);
		expect(module.requires).toEqual(["deploymentMode"]);
		expect(module.optional).toEqual(["logger"]);
		expect(module.section).toBeUndefined();
		expect(module.contributes).toBeUndefined();
		expect(module.replicaSafety).toBeUndefined();
	});

	it("fills the slot with the development sender, logging through the composition's logger, in development on one replica", async () => {
		const { logger, calls } = recordingLogger();
		for (const deploymentMode of ["single", "unset"] as const) {
			const sender = await provide({ environment: "development" }, deploymentMode, logger);
			expect(sender.kind).toBe("standard-development");
			await sender.send(SEND);
		}
		expect(calls).toHaveLength(2);
		expect((await provide({ environment: " Test " }, "single")).kind).toBe("standard-development");
	});

	it("is told the environment the configuration was selected by, and refuses a name it cannot read", async () => {
		expectTypeOf<
			StandardDevelopmentMailSenderModuleOptions["environment"]
		>().toEqualTypeOf<string>();
		for (const environment of [undefined, 7, null]) {
			await expect(
				provide({ environment } as never, "single"),
				String(environment),
			).rejects.toThrow(
				new TypeError(
					"standard-development-mail-sender: environment must be the name the configuration was selected by",
				),
			);
		}
	});

	it("is refused under any environment but development or test: an allow-list, not a list of what to refuse", async () => {
		for (const [environment, named] of [
			["qa", "qa"],
			[" Local ", "local"],
			["preview", "preview"],
			["dev", "dev"],
			["", ""],
		] as const) {
			await expect(provide({ environment }, "single"), environment).rejects.toThrow(
				new RangeError(
					`standard-development-mail-sender logs every code it is handed, refused because the environment "${named}" is not development or test: install standard-smtp-mail-sender, or a mail sender of your own`,
				),
			);
		}
	});

	it("is refused where CONFIG_ENV says production or staging, whatever environment it is handed", async () => {
		for (const configEnv of ["staging", " PRODUCTION "]) {
			vi.stubEnv("CONFIG_ENV", configEnv);
			await expect(provide({ environment: "development" }, "single"), configEnv).rejects.toThrow(
				/refused because the environment is "(production|staging)"/,
			);
		}
	});

	it("is refused where the configuration was selected as production or staging, whatever its case and the whitespace around it, naming the environment", async () => {
		for (const [environment, named] of [
			["production", "production"],
			["staging", "staging"],
			[" Production\n", "production"],
			["STAGING", "staging"],
		] as const) {
			await expect(provide({ environment }, "single"), environment).rejects.toThrow(
				new RangeError(
					`standard-development-mail-sender logs every code it is handed, refused because the environment is "${named}": install standard-smtp-mail-sender, or a mail sender of your own`,
				),
			);
		}
	});

	it("is refused where NODE_ENV is production or staging, whatever environment it is handed", async () => {
		for (const nodeEnv of ["production", "Staging "]) {
			vi.stubEnv("NODE_ENV", nodeEnv);
			await expect(provide({ environment: "development" }, "single"), nodeEnv).rejects.toThrow(
				/refused because the environment is "(production|staging)"/,
			);
		}
	});

	it("is refused on a multi-replica deployment, and for a deployment mode it cannot read", async () => {
		await expect(provide({ environment: "development" }, "multi")).rejects.toThrow(
			/refused because core\.deployment\.mode is "multi"/,
		);
		for (const deploymentMode of [undefined, "MULTI"]) {
			await expect(
				provide({ environment: "development" }, deploymentMode as never),
				String(deploymentMode),
			).rejects.toThrow(
				new TypeError(
					'standard-development-mail-sender: deploymentMode must be "single", "multi" or "unset"',
				),
			);
		}
	});

	it("boots over core's configuration and fills the slot though nothing reads it, and a production environment refuses the boot", async () => {
		const handle = await createApp({
			modules: [standardDevelopmentMailSenderModule({ environment: "development" })],
			bootstrapComponents: {
				config: makeValidAppConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			expect((handle.components.mailSender as MailSender).kind).toBe("standard-development");
		} finally {
			await handle.dispose();
		}
		let refused: unknown;
		try {
			await createApp({
				modules: [standardDevelopmentMailSenderModule({ environment: "production" })],
				bootstrapComponents: {
					config: makeValidAppConfig(),
					pathResolver: (p: string) => p,
				} as never,
			});
		} catch (error) {
			refused = error;
		}
		expect(refused).toBeInstanceOf(BootError);
		expect((refused as BootError).message).toContain(
			'standard-development-mail-sender logs every code it is handed, refused because the environment is "production"',
		);
	});
});
