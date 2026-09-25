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
 * The errors an operator is told to look for are importable: the README and
 * the runbook name `MtlsRevocationUnavailableError` (an outage refusal's
 * cause) and its `MtlsRevocationSourceError` members, so a consumer can tell
 * them apart with `instanceof` rather than by name.
 */

import { describe, expect, it } from "vitest";
import * as mtls from "#/index.mjs";

describe("@o3co/auth-provider-mtls exports", () => {
	it("exports the outage refusal's cause and its members", () => {
		const member = new mtls.MtlsRevocationSourceError({
			source: "crl",
			url: "http://crl.test/int.crl",
			reason: "fetch_failed",
			detail: "network_error (ECONNREFUSED)",
		});
		const cause = new mtls.MtlsRevocationUnavailableError("CN=client", [member]);

		expect(cause).toBeInstanceOf(AggregateError);
		expect(cause.errors).toEqual([member]);
		expect(member.message).toBe(
			"crl http://crl.test/int.crl: fetch_failed — network_error (ECONNREFUSED)",
		);
		expect(cause.message).toBe("revocation status could not be determined for CN=client");
	});
});
