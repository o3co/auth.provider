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
 * The mail sender the template installs behind core's `mailSender` slot,
 * both from `@o3co/auth-provider-standard`: the development sender where the
 * configuration was selected as development — the name `app.mts` defaults
 * to — the SMTP sender's module under any other name, and none when
 * `buildModules` is told no name. A deployment's own sender modules, passed
 * as `mailSenderModules`, replace that choice under every name. Nothing in
 * the template reads the slot: this is the wiring alone.
 */

import { defineModule, type MailSender, type Module } from "@o3co/auth-provider-core";
import {
	standardDevelopmentMailSenderModule,
	standardSmtpMailSenderModule,
} from "@o3co/auth-provider-standard";
import { afterEach, describe, expect, it } from "vitest";
import { buildModules } from "#/buildModules.mjs";
import {
	type Composition,
	compose,
	resolveConfig,
	SINGLE_ENV,
} from "./all-modules-composition.fixture.mjs";

const DEVELOPMENT = standardDevelopmentMailSenderModule({ environment: "development" }).name;
const SMTP = standardSmtpMailSenderModule.name;

/** A deployment's own sender, built at boot so the slot holds it with nothing reading it. */
const OWN_SENDER: MailSender = {
	kind: "deployment-own",
	send: async () => ({ outcome: "delivered" }),
};
const ownSenderModule: Module = defineModule({
	name: "deployment-own-mail-sender",
	lifecycle: { mailSender: { eager: true } },
	provides: { mailSender: () => OWN_SENDER },
});
const OWN = ownSenderModule.name;

/** The mail sender modules `buildModules` lists for `environment`. */
const senders = (
	environment: string | undefined,
	mailSenderModules?: readonly Module[],
): string[] =>
	buildModules(resolveConfig(SINGLE_ENV), {
		...(environment === undefined ? {} : { environment }),
		...(mailSenderModules === undefined ? {} : { mailSenderModules }),
	})
		.map((module) => module.name)
		.filter((name) => name === DEVELOPMENT || name === SMTP || name === OWN);

const ENVIRONMENTS = ["development", "production", "staging", "test", "Development"] as const;

describe("the template's mail sender", () => {
	let current: Composition | undefined;
	afterEach(async () => {
		await current?.handle.dispose();
		current = undefined;
	});

	it("is the development sender in development, and none where no environment is named", () => {
		expect(senders("development")).toEqual([DEVELOPMENT]);
		expect(senders(undefined)).toEqual([]);
	});

	it("is the SMTP sender's module under any other environment", () => {
		for (const environment of ["production", "staging", "test", "Development"]) {
			expect(senders(environment), environment).toEqual([SMTP]);
		}
	});

	it("fills the slot with the development sender when the composition boots in development", async () => {
		current = await compose({ environment: "development" });
		expect((current.handle.components.mailSender as MailSender | undefined)?.kind).toBe(
			"standard-development",
		);
	});

	it("boots in production with the SMTP sender's module installed and no SMTP settings, building no sender where nothing reads the slot", async () => {
		current = await compose();
		expect(current.modules.map((module) => module.name)).toContain(SMTP);
		expect(current.handle.components.mailSender).toBeUndefined();
	});

	describe("given the deployment's own sender modules", () => {
		it("installs them in place of the bundled sender, under every environment name and none", () => {
			for (const environment of [...ENVIRONMENTS, undefined]) {
				expect(senders(environment, [ownSenderModule]), String(environment)).toEqual([OWN]);
			}
		});

		it("installs no sender at all when the list is empty", () => {
			for (const environment of [...ENVIRONMENTS, undefined]) {
				expect(senders(environment, []), String(environment)).toEqual([]);
			}
		});

		it.each(["development", "production"])(
			"fills the slot with the deployment's sender when the composition boots in %s",
			async (environment) => {
				current = await compose({ environment, mailSenderModules: [ownSenderModule] });
				const names = current.modules.map((module) => module.name);
				expect(names).toContain(OWN);
				expect(names).not.toContain(DEVELOPMENT);
				expect(names).not.toContain(SMTP);
				expect(current.handle.components.mailSender).toBe(OWN_SENDER);
			},
		);

		it("boots in production with no sender when the list is empty", async () => {
			current = await compose({ environment: "production", mailSenderModules: [] });
			const names = current.modules.map((module) => module.name);
			expect(names).not.toContain(DEVELOPMENT);
			expect(names).not.toContain(SMTP);
			expect(current.handle.components.mailSender).toBeUndefined();
		});
	});
});
