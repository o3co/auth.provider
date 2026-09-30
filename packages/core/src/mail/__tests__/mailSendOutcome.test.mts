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
 * The one reading of what a `MailSender` answered: `delivered` and
 * `refused_at_limit` only as the port states them, and anything else an
 * outage — never "sent".
 */

import { describe, expect, it } from "vitest";
import { mailSendOutcome } from "#/index.mjs";

describe("mailSendOutcome", () => {
	it("reads the port's two answers as they are", () => {
		expect(mailSendOutcome({ outcome: "delivered" })).toBe("delivered");
		expect(mailSendOutcome({ outcome: "refused_at_limit" })).toBe("refused_at_limit");
		expect(mailSendOutcome(Object.freeze({ outcome: "delivered" }))).toBe("delivered");
		expect(
			mailSendOutcome(Object.assign(Object.create(null), { outcome: "refused_at_limit" })),
		).toBe("refused_at_limit");
	});

	it("reads anything else as an outage: no answer, another outcome, another shape, or more than the outcome", () => {
		for (const answer of [
			undefined,
			null,
			{},
			"delivered",
			true,
			[],
			[{ outcome: "delivered" }],
			{ outcome: "sent" },
			{ outcome: "DELIVERED" },
			{ outcome: undefined },
			{ outcome: "delivered", messageId: "m-1" },
			{ outcome: "refused_at_limit", retryAfterMs: 1000 },
			{ ok: true },
		]) {
			expect(mailSendOutcome(answer), JSON.stringify(answer)).toBe("outage");
		}
	});

	it("reads an answer that is no plain record of data as an outage: an accessor, an unreadable object, a class instance", () => {
		let reads = 0;
		const flipping = {
			get outcome() {
				reads += 1;
				return reads === 1 ? "delivered" : "refused_at_limit";
			},
		};
		expect(mailSendOutcome(flipping)).toBe("outage");
		const throwing = new Proxy(
			{},
			{
				ownKeys: () => {
					throw new Error("unreadable");
				},
			},
		);
		expect(mailSendOutcome(throwing)).toBe("outage");
		class Answer {
			readonly outcome = "delivered";
		}
		expect(mailSendOutcome(new Answer())).toBe("outage");
	});
});
