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
 * The MFA routes admit a session through the session lifecycle port, which
 * a composition wires beside its user-session store: a session whose
 * lifecycle record is closing is not admitted. Without the port the routes
 * refuse to build.
 */

import {
	createInMemorySessionLifecycleStore,
	createInMemoryUserSessionStore,
	createMemoryMfaFactorStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MfaRoutesOptions } from "#/routes.mjs";
import { createMfaRouter } from "#/routes.mjs";
import { ALICE, boot, configFor, disposeAll, refusal } from "./moduleHarness.mjs";
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
			sessionLifecycleStore: lifecycle,
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

	it("refuse to boot with userSessionStore wired and no sessionLifecycleStore, naming both slots", async () => {
		const err = await refusal({ sessionLifecycleStore: null });
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ kind: "sessionRequirements", name: "mfa", module: "mfa" });
		expect((err.cause as Error).message).toMatch(
			/^mfa: userSessionStore is wired, but sessionLifecycleStore is not\.[\s\S]*Install sessionLifecycleModule/,
		);
	});

	it("refuse to build the router with a user-session store and no session lifecycle port", () => {
		const options = {
			admission: { userSessionStore: createInMemoryUserSessionStore() },
		} as unknown as MfaRoutesOptions;
		expect(() => createMfaRouter(options)).toThrow(
			/userSessionStore is wired, but sessionLifecycleStore is not/,
		);
	});
});
