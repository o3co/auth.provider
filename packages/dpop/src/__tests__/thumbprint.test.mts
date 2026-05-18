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
import { computeJkt } from "#/thumbprint.mjs";

describe("computeJkt — RFC 7638 SHA-256 JWK thumbprint", () => {
	it("matches the RFC 9449 §B.1 worked example", async () => {
		// RFC 9449 Appendix B example JWK (P-256 public key)
		const jwk = {
			kty: "EC",
			x: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
			y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
			crv: "P-256",
		} as const;
		const jkt = await computeJkt(jwk);
		// The RFC 9449 Appendix B expected JKT value (SHA-256 base64url of canonical JWK)
		expect(jkt).toBe("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
	});
});
