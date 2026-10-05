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
 * The refusal a client-record boundary rejects with: recognised by its
 * global brand alone, so a refusal from another constructor (another loaded
 * copy of core) reads the same, and a wrapper around one does not.
 */

import { describe, expect, it, vi } from "vitest";
import { loggableError } from "#/logging/loggableError.mjs";
import {
	ClientRecordRefusedError,
	isClientRecordRefused,
} from "#/repositories/clientRecordRefused.mjs";
import { logClientRepositoryUnavailable } from "#/repositories/clientRepositoryUnavailable.mjs";

const BRAND = Symbol.for("@o3co/auth-provider-core/client-record-refused");

/** A refusal as another loaded copy of core would build it: its own constructor, the same brand. */
class OtherCopyRefusal extends Error {
	constructor() {
		super("client record refused");
		Object.defineProperty(this, BRAND, { value: true });
	}
}

describe("ClientRecordRefusedError", () => {
	it("is an Error, frozen, carrying the global brand on itself", () => {
		const refusal = new ClientRecordRefusedError();
		expect(refusal).toBeInstanceOf(Error);
		expect(refusal.name).toBe("ClientRecordRefusedError");
		expect(Object.isFrozen(refusal)).toBe(true);
		expect(Object.hasOwn(refusal, BRAND)).toBe(true);
		expect((refusal as unknown as Record<symbol, unknown>)[BRAND]).toBe(true);
	});

	it("names its cause as a code a log line keeps, and nothing of a client", () => {
		const projection = loggableError(new ClientRecordRefusedError());
		expect(projection).toMatchObject({
			name: "ClientRecordRefusedError",
			reason: "client_record_refused",
		});
	});
});

describe("isClientRecordRefused", () => {
	it("is true for core's refusal and for one another constructor built with the brand", () => {
		expect(isClientRecordRefused(new ClientRecordRefusedError())).toBe(true);
		expect(isClientRecordRefused(new OtherCopyRefusal())).toBe(true);
		expect(new OtherCopyRefusal()).not.toBeInstanceOf(ClientRecordRefusedError);
	});

	it("is false for an outage, a wrapper around a refusal, and anything not an object", () => {
		const refusal = new ClientRecordRefusedError();
		for (const value of [
			new Error("connection reset"),
			new Error("wrapped", { cause: refusal }),
			{ cause: refusal },
			{ [BRAND]: false },
			{ [BRAND]: "true" },
			Object.create(refusal),
			null,
			undefined,
			"client_record_refused",
			42,
		]) {
			expect(isClientRecordRefused(value), String(value)).toBe(false);
		}
	});

	it("never throws, answering false for a value whose read throws", () => {
		const hostile = new Proxy(
			{},
			{
				get() {
					throw new Error("read failed");
				},
				getOwnPropertyDescriptor() {
					throw new Error("read failed");
				},
			},
		);
		expect(isClientRecordRefused(hostile)).toBe(false);
	});
});

describe("logClientRepositoryUnavailable — a refusal", () => {
	it("names the refusal as the cause on the outage line", () => {
		const logger = { error: vi.fn() };
		logClientRepositoryUnavailable(
			logger,
			{ step: "find", site: "authorize", clientId: "client-1" },
			new ClientRecordRefusedError(),
		);
		expect(logger.error).toHaveBeenCalledTimes(1);
		const [line, message] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
		expect(message).toBe("client_repository_unavailable");
		expect(line).toMatchObject({
			site: "authorize",
			step: "find",
			clientId: "client-1",
			err: { name: "ClientRecordRefusedError", reason: "client_record_refused" },
		});
	});
});
