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
import { describe, expect, it } from "vitest";
import { MtlsError, MtlsRevocationSourceError } from "#/errors.mjs";

describe("MtlsError", () => {
	it("hard-codes code to invalid_certificate regardless of reason", () => {
		const err = new MtlsError("cert_expired", "certificate has expired");
		expect(err.code).toBe("invalid_certificate");
		expect(err.reason).toBe("cert_expired");
	});

	it("preserves message and optional detail bag", () => {
		const err = new MtlsError("chain_validation_failed", "chain broken", {
			step: "intermediate expired",
		});
		expect(err.message).toBe("chain broken");
		expect(err.detail).toEqual({ step: "intermediate expired" });
	});

	it("omits detail property when not provided", () => {
		const err = new MtlsError("malformed_header", "bad header");
		expect(err.detail).toBeUndefined();
	});

	it("is instanceof Error so callers can catch generically", () => {
		const err = new MtlsError("cert_decode_failed", "cannot decode PEM");
		expect(err).toBeInstanceOf(Error);
		expect(err).toBeInstanceOf(MtlsError);
	});

	it("accepts all MtlsReasonCode variants without TypeScript error", () => {
		// Each variant should be constructable — validates the union is correct.
		const reasons = [
			"malformed_header",
			"unknown_dialect",
			"cert_decode_failed",
			"cert_expired",
			"cert_not_yet_valid",
			"chain_validation_failed",
			"trusted_cas_unconfigured",
			"tls_peer_unavailable",
			"untrusted_proxy",
		] as const;
		for (const reason of reasons) {
			const err = new MtlsError(reason, "test");
			expect(err.reason).toBe(reason);
		}
	});
});

describe("MtlsRevocationSourceError — a source's own text, one line and capped", () => {
	it("names the url, the detail and the subject on one line, each capped", () => {
		const err = new MtlsRevocationSourceError({
			source: "ocsp",
			url: `http://ocsp.test/\u0085\u2028${"u".repeat(10_000)}`,
			reason: "unexpected_content_type",
			detail: `expected application/ocsp-response, got text/html\u202e\u2066${"d".repeat(10_000)}`,
			subject: `CN=clïent\u2028${"s".repeat(10_000)}`,
		});
		expect({
			// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be logged.
			unsafe: /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/.test(
				`${err.message}${err.url}${err.subject}`,
			),
			messageWithin: err.message.length <= 3 * 256 + 64,
			url: [err.url?.startsWith("http://ocsp.test/??u"), (err.url ?? "").length <= 256],
			subject: [err.subject.startsWith("CN=clïent?s"), err.subject.length <= 256],
		}).toEqual({
			unsafe: false,
			messageWithin: true,
			url: [true, true],
			subject: [true, true],
		});
	});
});
