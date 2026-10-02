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

// no-mfa:omit-file

/**
 * The template's MFA switch under the name production, where the MFA stores
 * must be shared: both on Redis, as a production deployment selects them.
 * ioredis is a stand-in, as in `all-modules-composition.multi.test.mts`:
 * nothing here issues a command, and the stores' durability check names what
 * it could not read and goes on. `packages/redis` runs the stores against a
 * real server.
 */

import { BootError } from "@o3co/auth-provider-core";
import { MFA_DEVELOPMENT_SAMPLE_KEY } from "@o3co/auth-provider-mfa";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type Composition, compose, SINGLE_ENV } from "./all-modules-composition.fixture.mjs";

vi.mock("ioredis", () => {
	// Constructible, quits cleanly, answers the readiness probe's `ping`;
	// every other command resolves to nothing.
	const explicit: Record<string, unknown> = {
		on: () => undefined,
		quit: async () => "OK",
		disconnect: () => undefined,
		ping: async () => "PONG",
	};
	const makeMockRedis = (): object =>
		new Proxy(
			{},
			{
				get(_target, prop) {
					// A function-valued `then` would make the instance a thenable.
					if (typeof prop !== "string" || prop === "then") return undefined;
					if (prop === "duplicate") return makeMockRedis;
					if (prop in explicit) return explicit[prop];
					return async () => null;
				},
			},
		);
	function MockRedis(): object {
		return makeMockRedis();
	}
	return { Redis: MockRedis, default: MockRedis };
});

let current: Composition | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** MFA required in production, both MFA stores on Redis, a key of the deployment's own and an SMTP relay. */
const PRODUCTION_ENV: Readonly<Record<string, string>> = {
	...SINGLE_ENV,
	MFA_MODE: "required",
	ADAPTERS_MFA_FACTOR_STORE: "redis",
	ADAPTERS_MFA_TRANSACTION_STORE: "redis",
	REDIS_CLIENTS_URL: "redis://redis.test:6379",
	MFA_ENCRYPTION_KEY: Buffer.alloc(32, 9).toString("base64"),
	STANDARD_SMTP_MAIL_SENDER_HOST: "smtp.auth.test",
	STANDARD_SMTP_MAIL_SENDER_FROM: "auth@auth.test",
};

/** An error's message with every cause's under it. */
const textOf = (err: unknown): string => {
	const parts: string[] = [];
	for (let at: unknown = err; at instanceof Error; at = at.cause) parts.push(at.message);
	return parts.join(" <- ");
};

const refusal = (composing: Promise<Composition>): Promise<unknown> =>
	composing.then(
		(composition) => {
			current = composition;
			return undefined;
		},
		(caught: unknown) => caught,
	);

describe("MFA_MODE=required under the name production, the MFA stores on Redis", () => {
	it("boots, the requirement registered as the second-factor authority", async () => {
		current = await compose({ env: PRODUCTION_ENV, environment: "production" });
		const names = current.modules.map((m) => m.name);
		expect(names).toContain("redis-mfa-factor-store");
		expect(names).toContain("redis-mfa-transaction-store");
		expect(
			current.handle.components.sessionRequirementResolver?.get("mfa")?.secondFactorAuthority,
		).toBe(true);
	});

	it("refuses the development sample key, naming MFA_ENCRYPTION_KEY and quoting no key", async () => {
		const err = await refusal(
			compose({
				env: { ...PRODUCTION_ENV, MFA_ENCRYPTION_KEY: MFA_DEVELOPMENT_SAMPLE_KEY },
				environment: "production",
			}),
		);
		expect(err).toBeInstanceOf(BootError);
		expect(textOf(err)).toContain("MFA_ENCRYPTION_KEY");
		expect(textOf(err)).not.toContain(MFA_DEVELOPMENT_SAMPLE_KEY);
	});

	it("refuses without an SMTP relay, naming STANDARD_SMTP_MAIL_SENDER_HOST", async () => {
		const { STANDARD_SMTP_MAIL_SENDER_HOST: _host, ...env } = PRODUCTION_ENV;
		const err = await refusal(compose({ env, environment: "production" }));
		expect(err).toBeInstanceOf(BootError);
		expect(textOf(err)).toContain("STANDARD_SMTP_MAIL_SENDER_HOST");
	});
});
