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
 * The MFA routes admit a session through the session lifecycle port when one
 * is wired: a session whose lifecycle record is closing is not admitted.
 */

import {
	createInMemorySessionLifecycleStore,
	createMemoryMfaFactorStore,
	defineModule,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ALICE, boot, configFor, disposeAll } from "./moduleHarness.mjs";
import { freezeClock, seedTotp, signInWithTotp, T0, thawClock } from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
	vi.restoreAllMocks();
});

describe("the MFA routes and the session lifecycle", () => {
	it("refuse a session whose lifecycle record is closing, after admitting it while it was active", async () => {
		const lifecycle = createInMemorySessionLifecycleStore();
		const factorStore = createMemoryMfaFactorStore();
		const built = await boot({
			config: configFor("optional"),
			factorStore,
			extraModules: [
				defineModule({
					name: "test:session-lifecycle-store",
					provides: { sessionLifecycleStore: () => lifecycle },
				}),
			],
		});
		const totp = await seedTotp(factorStore);
		const { agent, sid } = await signInWithTotp(
			built.app,
			built.userSessionStore as UserSessionStore,
			totp,
		);
		await lifecycle.open(sid, ALICE.id, new Date(T0 + 3_600_000));
		expect((await agent.get("/session/mfa/factors")).status).toBe(200);

		await lifecycle.beginClose(sid, {
			cause: "rp_logout",
			steps: ["tokens"],
			perParticipant: [],
			retainMs: 0,
		});
		const res = await agent.get("/session/mfa/factors");
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
	});
});
