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
 * What an operator is told when something failed, and what they are not
 * (#593, D18).
 *
 * Core reports every cause it turns into a typed answer, because a 503 says
 * that something broke without saying what. The error it hands over may be an
 * upstream's, and an upstream's error carries whatever the upstream echoed —
 * a request body, a token, a header it did not like. So the report is built
 * from an allowlist rather than redacted from the error: a redaction list is
 * a list of the leaks somebody has already thought of.
 */

import { describe, expect, it, vi } from "vitest";
import {
	createSanitizedAuditSink,
	createSanitizedLogger,
	createSanitizedReporter,
} from "#/report.mjs";

const SENTINEL = "s3cret-refresh-token-do-not-log";

const spyLogger = () => {
	const warn = vi.fn();
	const error = vi.fn();
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn,
		error,
		fatal: vi.fn(),
		child: vi.fn(),
	};
	return { logger: logger as never, warn, error };
};

describe("createSanitizedReporter", () => {
	it("reports where it failed, for which grant, under which correlation", () => {
		const { logger, warn } = spyLogger();
		createSanitizedReporter(logger)({
			during: "refresh",
			error: new Error("boom"),
			grantId: "g1",
			correlationId: "req-1",
		});
		expect(warn).toHaveBeenCalledTimes(1);
		expect(warn.mock.calls[0]?.[0]).toMatchObject({
			event: "federation_grant.failure",
			during: "refresh",
			grantId: "g1",
			correlationId: "req-1",
		});
	});

	it("never carries the error, its message, its cause or its stack", () => {
		const { logger, warn } = spyLogger();
		const upstream = new Error(`upstream rejected ${SENTINEL}`);
		upstream.stack = `Error: ${SENTINEL}\n    at somewhere`;
		(upstream as { response?: unknown }).response = { body: SENTINEL };
		upstream.cause = new Error(SENTINEL);

		createSanitizedReporter(logger)({
			during: "upstream",
			error: upstream,
			grantId: "g1",
			correlationId: "req-1",
		});

		const serialized = JSON.stringify(warn.mock.calls[0]);
		expect(serialized).not.toContain(SENTINEL);
		expect(serialized).not.toContain("somewhere");
	});

	it("classifies the failure from a closed set, never from an arbitrary name", () => {
		const { logger, warn } = spyLogger();
		const report = createSanitizedReporter(logger);

		const aborted = new Error("aborted");
		aborted.name = "AbortError";
		report({ during: "upstream", error: aborted, grantId: "g", correlationId: "c" });
		expect(warn.mock.calls[0]?.[0]).toMatchObject({ classification: "aborted" });

		report({ during: "upstream", error: new TypeError("x"), grantId: "g", correlationId: "c" });
		expect(warn.mock.calls[1]?.[0]).toMatchObject({ classification: "type_error" });

		const invented = new Error("x");
		invented.name = `Leaked-${SENTINEL}`;
		report({ during: "upstream", error: invented, grantId: "g", correlationId: "c" });
		expect(warn.mock.calls[2]?.[0]).toMatchObject({ classification: "unknown" });
		expect(JSON.stringify(warn.mock.calls[2])).not.toContain(SENTINEL);
	});

	it("names the Store refusing this deployment's credential, and nothing of its message", () => {
		// The foundation adapter's refusal — a Store's 401 or 403 with a Bearer
		// challenge (StoreCredentialRefusedError). Recognised by name, as every
		// classification is: this package does not depend on the adapter.
		const { logger, warn } = spyLogger();
		const refused = new Error(`the Store at https://store.test refused ${SENTINEL}`);
		refused.name = "StoreCredentialRefusedError";
		createSanitizedReporter(logger)({
			during: "callback_identity_lookup",
			error: refused,
			grantId: "g",
			correlationId: "c",
		});
		expect(warn.mock.calls[0]?.[0]).toMatchObject({ classification: "store_credential_refused" });
		expect(JSON.stringify(warn.mock.calls[0])).not.toContain(SENTINEL);
	});

	it("names a Store that could not be reached, or answered unreadably, and nothing of its message", () => {
		// The foundation adapter's StoreTransportError: a refused connection, a
		// TLS failure, a connection closed first, a malformed answer, a body that broke mid-read.
		const { logger, warn } = spyLogger();
		const failed = new Error(`request to https://store.test could not be reached ${SENTINEL}`);
		failed.name = "StoreTransportError";
		createSanitizedReporter(logger)({
			during: "callback_identity_lookup",
			error: failed,
			grantId: "g",
			correlationId: "c",
		});
		expect(warn.mock.calls[0]?.[0]).toMatchObject({ classification: "store_transport_failed" });
		expect(JSON.stringify(warn.mock.calls[0])).not.toContain(SENTINEL);
	});

	it("survives a failure that is not an error at all", () => {
		const { logger, warn } = spyLogger();
		createSanitizedReporter(logger)({
			during: "storage",
			error: { toJSON: () => SENTINEL },
			grantId: "g",
			correlationId: "c",
		});
		expect(JSON.stringify(warn.mock.calls[0])).not.toContain(SENTINEL);
		expect(warn.mock.calls[0]?.[0]).toMatchObject({ classification: "unknown" });
	});
});

describe("createSanitizedLogger", () => {
	it("passes the fields a middleware logs, without the error objects among them", () => {
		// The shared client-authentication and rate-limit middleware log their
		// repository failures with the raw error in the structured payload.
		// They are handed this facade rather than the deployment's logger, so a
		// repository that embeds an upstream response in its error does not put
		// it into this route's logs.
		const { logger, error } = spyLogger();
		createSanitizedLogger(logger).error(
			{ event: "client_auth.repository_error", clientId: "worker", err: new Error(SENTINEL) },
			"repository failed",
		);
		expect(error).toHaveBeenCalledTimes(1);
		const [payload, message] = error.mock.calls[0] ?? [];
		expect(message).toBe("repository failed");
		expect(payload).toMatchObject({ event: "client_auth.repository_error", clientId: "worker" });
		expect(JSON.stringify(error.mock.calls[0])).not.toContain(SENTINEL);
	});

	it("keeps the fields it has decided to carry, and replaces every other", () => {
		// An allowlist of NAMES, not a test of types. This was a type check
		// first — scalars through, objects redacted — and review found the hole
		// it leaves: the rate-limit guard turns a limiter's exception into its
		// `message` and logs `{ error: <that string> }`, so a driver naming a
		// connection string in its error passed straight through as an
		// ordinary string.
		const { logger, error } = spyLogger();
		createSanitizedLogger(logger).error({
			tag: "federation_grants",
			ip: "203.0.113.7",
			mode: "closed",
			error: `redis://user:${SENTINEL}@limiter:6379 refused`,
			count: 3,
			nested: { deep: SENTINEL },
		});
		expect(error.mock.calls[0]?.[0]).toEqual({
			tag: "federation_grants",
			ip: "203.0.113.7",
			mode: "closed",
			// Redacted rather than dropped: an operator can still see there was one.
			error: "[redacted]",
			count: "[redacted]",
			nested: "[redacted]",
		});
		expect(JSON.stringify(error.mock.calls[0])).not.toContain(SENTINEL);
	});

	it("carries an audited error under cause, and redacts any other value there", () => {
		// Core's `rate_limit.unavailable` names the limiter's error as
		// `details.cause`, `auditedError`'s `{ name, code?, cause? }` — bounded
		// and free of the error's text, so the trail keeps it. Anything else
		// under that key is not an audited error and is redacted.
		const recorded: unknown[] = [];
		const sanitized = createSanitizedAuditSink({
			kind: "test",
			record: async (event) => {
				recorded.push(event);
			},
		});
		void sanitized.record({
			timestamp: new Date(),
			type: "rate_limit.unavailable",
			details: {
				tag: "federation_grants",
				cause: { name: "ReplyError", code: "ECONNRESET", cause: { name: "Error" } },
			},
		});
		void sanitized.record({
			timestamp: new Date(),
			type: "rate_limit.unavailable",
			// What a JavaScript emitter could hand over: the type refuses it.
			details: { tag: "federation_grants", cause: { name: "Error", message: SENTINEL } as never },
		});
		expect((recorded[0] as { details: Record<string, unknown> }).details).toEqual({
			tag: "federation_grants",
			cause: { name: "ReplyError", code: "ECONNRESET", cause: { name: "Error" } },
		});
		expect((recorded[1] as { details: Record<string, unknown> }).details).toEqual({
			tag: "federation_grants",
			cause: "[redacted]",
		});
		expect(JSON.stringify(recorded)).not.toContain(SENTINEL);
	});

	it.each([
		["a name carrying CRLF", { name: "Error\r\nX-Injected: 1" }],
		["a code carrying a double quote", { name: "Error", code: 'E"CODE' }],
		["a nested cause carrying non-ASCII", { name: "Error", cause: { name: "Erreur\u00e9" } }],
	])("redacts a cause with %s, which auditedError never writes", (_label, cause) => {
		// `auditedError` sanitises every name and code; a value outside those
		// characters did not come from it, so it is not carried.
		const recorded: unknown[] = [];
		const sanitized = createSanitizedAuditSink({
			kind: "test",
			record: async (event) => {
				recorded.push(event);
			},
		});
		void sanitized.record({
			timestamp: new Date(),
			type: "rate_limit.unavailable",
			details: { tag: "federation_grants", cause: cause as never },
		});
		expect((recorded[0] as { details: Record<string, unknown> }).details).toEqual({
			tag: "federation_grants",
			cause: "[redacted]",
		});
	});

	it("applies the same allowlist to an audit event's details", () => {
		// `rate_limit.unavailable` carries the same stringified exception the
		// log line does, on a channel the logger facade never sees.
		const { logger } = spyLogger();
		void logger;
		const recorded: unknown[] = [];
		const sanitized = createSanitizedAuditSink({
			kind: "test",
			record: async (event) => {
				recorded.push(event);
			},
		});
		void sanitized.record({
			timestamp: new Date(),
			type: "rate_limit.unavailable",
			ip: "203.0.113.7",
			details: { tag: "federation_grants", error: `secret ${SENTINEL}` },
		});
		expect(JSON.stringify(recorded)).not.toContain(SENTINEL);
		expect((recorded[0] as { details: Record<string, unknown> }).details).toEqual({
			tag: "federation_grants",
			error: "[redacted]",
		});
	});

	it("passes a string-first call through as it is", () => {
		const { logger, error } = spyLogger();
		createSanitizedLogger(logger).error("plain message");
		expect(error).toHaveBeenCalledWith("plain message");
	});

	it("is a logger, so every level a middleware may reach for is there", () => {
		const { logger } = spyLogger();
		const sanitized = createSanitizedLogger(logger);
		for (const level of ["trace", "debug", "info", "warn", "error", "fatal"] as const) {
			expect(typeof sanitized[level]).toBe("function");
		}
		expect(typeof sanitized.child).toBe("function");
	});

	it("sanitizes a child logger's payloads too", () => {
		const { logger, error } = spyLogger();
		(logger as unknown as { child: ReturnType<typeof vi.fn> }).child.mockReturnValue(logger);
		createSanitizedLogger(logger)
			.child({ route: "token" })
			.error({ err: new Error(SENTINEL) });
		expect(JSON.stringify(error.mock.calls[0])).not.toContain(SENTINEL);
	});
});
