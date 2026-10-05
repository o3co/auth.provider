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
import { createInMemoryUserSessionStore } from "../memory/userSessionStore.mjs";
import {
	runSecondFactorUpdateContract,
	runUserSessionStoreContract,
} from "./userSessionStore.contract.mjs";

describe("the memory user session store", () => {
	runUserSessionStoreContract(async () => createInMemoryUserSessionStore());
	// The step-up capability, which the memory store claims (the MFA ADR's D9).
	runSecondFactorUpdateContract(async () => createInMemoryUserSessionStore());
});

describe("the memory user session store keeps a federated session's upstreamAuthTime", () => {
	const UPSTREAM = new Date(Date.now() - 600_000);
	const input = (sid: string, upstreamAuthTime: Date | null) => ({
		sid,
		sub: "user-1",
		authTime: new Date(Date.now() - 1_000),
		expiresAt: new Date(Date.now() + 3_600_000),
		claims: {},
		amr: ["fed"],
		authentication: {
			primary: "fed",
			federation: "google",
			upstreamAmr: undefined,
			mfaAt: undefined,
			upstreamAuthTime,
		},
	});

	it("round-trips a Date and null through create and get, and through a second factor", async () => {
		const store = createInMemoryUserSessionStore();
		await store.create(input("sid-upstream", UPSTREAM));
		await store.create(input("sid-null", null));
		expect((await store.get("sid-upstream"))?.authentication?.upstreamAuthTime).toEqual(UPSTREAM);
		expect((await store.get("sid-null"))?.authentication?.upstreamAuthTime).toBeNull();
		const stepped = await store.recordSecondFactor("sid-upstream", {
			amr: ["otp", "mfa"],
			at: new Date(),
		});
		expect(stepped?.authentication?.upstreamAuthTime).toEqual(UPSTREAM);
		expect((await store.get("sid-upstream"))?.authentication?.upstreamAuthTime).toEqual(UPSTREAM);
		await store.recordSecondFactor("sid-null", { amr: ["otp", "mfa"], at: new Date() });
		expect((await store.get("sid-null"))?.authentication?.upstreamAuthTime).toBeNull();
	});

	it("answers copies: changing what get answered changes nothing stored", async () => {
		const store = createInMemoryUserSessionStore();
		await store.create(input("sid-copy", UPSTREAM));
		(await store.get("sid-copy"))?.authentication?.upstreamAuthTime?.setTime(0);
		expect((await store.get("sid-copy"))?.authentication?.upstreamAuthTime).toEqual(UPSTREAM);
	});
});
