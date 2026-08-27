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
import { MtlsError } from "#/errors.mjs";

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
