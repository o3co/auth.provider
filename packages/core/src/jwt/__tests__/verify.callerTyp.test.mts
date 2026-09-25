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
 * The `typ` header is the caller's text, read before any signature is
 * checked: whoever holds no key at all still chooses it. It reaches two
 * places an operator reads — the `jwt_verify_rejected` line's `typ` field,
 * and the verdict's message, which a caller's log carries as the projected
 * error's `detail` — and in both it is sanitised and capped, as any other
 * caller-written text on a log line is.
 */

import { createSecretKey } from "node:crypto";
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { JwtVerificationError, type JwtVerifyOptions, verifyJwt } from "#/jwt/verify.mjs";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { loggableError } from "#/logging/loggableError.mjs";

const SECRET = "test-secret-32-bytes-long-string12";
const ISSUER = "https://example.com";

const options: JwtVerifyOptions = {
	type: "access_token",
	expectedIssuer: ISSUER,
	revocation: "none",
};

/** A line break, a terminal escape, a NUL and a bell, then 10 000 characters. */
const HOSTILE = `at+jwt\r\nFORGED jwt_verify_rejected reason=none\u001b[31m\u0000\u0007${"A".repeat(10_000)}`;

/** Any character a log line must not carry raw: a control character or a line break. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be logged.
const CONTROL = /[\u0000-\u001f\u007f]/;

/**
 * What an assertion needs to know of a logged string, and no more: a failure
 * prints this, not ten thousand characters.
 */
const shapeOf = (text: string) => ({
	control: CONTROL.test(text),
	within200: text.length <= 200,
	head: text.slice(0, 16),
	tail: text.slice(-3),
});

const spyLogger = () => {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: () => logger,
	};
	return logger;
};

const withTyp = (typ: string): Promise<string> =>
	new SignJWT({ sub: "user-1" })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ })
		.setIssuer(ISSUER)
		.setIssuedAt()
		.setExpirationTime("5m")
		.sign(createSecretKey(Buffer.from(SECRET)));

describe("verifyJwt — a typ header the caller wrote", () => {
	it("logs jwt_verify_rejected once, with the typ sanitised and capped", async () => {
		const logger = spyLogger();
		const keyStore = createSymmetricKeyStore(SECRET, "v0");

		await expect(
			verifyJwt(await withTyp(HOSTILE), keyStore, {
				...options,
				logger: logger as unknown as Logger,
			}),
		).rejects.toMatchObject({ reason: "typ" });

		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.error).not.toHaveBeenCalled();
		const [line, event] = logger.warn.mock.calls[0] as [Record<string, unknown>, string];
		expect(event).toBe("jwt_verify_rejected");
		expect(line.reason).toBe("typ");
		expect(typeof line.typ).toBe("string");
		expect(shapeOf(line.typ as string)).toEqual({
			control: false,
			within200: true,
			head: "at+jwt??FORGED j",
			tail: "...",
		});
	});

	it("builds the verdict's message from the sanitised, capped typ", async () => {
		const keyStore = createSymmetricKeyStore(SECRET, "v0");

		const err = await verifyJwt(await withTyp(HOSTILE), keyStore, options).catch((e: unknown) => e);

		expect(err).toBeInstanceOf(JwtVerificationError);
		const message = (err as Error).message;
		const typ = message.slice("JWT typ ".length, -" does not match expected at+jwt".length);
		expect({
			prefix: message.startsWith("JWT typ "),
			suffix: message.endsWith(" does not match expected at+jwt"),
			typ: shapeOf(typ),
		}).toEqual({
			prefix: true,
			suffix: true,
			typ: { control: false, within200: true, head: "at+jwt??FORGED j", tail: "..." },
		});
		expect(CONTROL.test(loggableError(err).detail ?? "")).toBe(false);
	});

	it("still names an ordinary wrong typ exactly", async () => {
		const logger = spyLogger();
		const keyStore = createSymmetricKeyStore(SECRET, "v0");

		const err = await verifyJwt(await withTyp("rt+jwt"), keyStore, {
			...options,
			logger: logger as unknown as Logger,
		}).catch((e: unknown) => e);

		expect((err as Error).message).toBe("JWT typ rt+jwt does not match expected at+jwt");
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: "typ", typ: "rt+jwt" }),
			"jwt_verify_rejected",
		);
	});
});
