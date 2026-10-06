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
 * The MFA routes' prefix, `mfa` (`mfa:ip:<ip>`): the MFA module claims it
 * and contributes no budget for it, so the deployment's limiter decides by
 * its own `limits` and `defaultLimit`. `mfa.rateLimit`, the budget the
 * section once held, refuses the boot naming it and what replaced it.
 */

import { afterEach, describe, expect, it } from "vitest";
import { MFA_RATE_LIMIT_PREFIX } from "#/index.mjs";
import { mfaModule } from "#/module.mjs";
import { boot, configFor, disposeAll, mfaSection, refusal } from "./moduleHarness.mjs";

afterEach(disposeAll);

describe("the MFA routes' prefix", () => {
	it("is mfa, which holds no colon", () => {
		expect(MFA_RATE_LIMIT_PREFIX).toBe("mfa");
	});

	it("is the one prefix the module claims, with no budget of its own", async () => {
		const claims = mfaModule().contributes?.rateLimitBudgets ?? {};
		expect(Object.keys(claims)).toEqual([MFA_RATE_LIMIT_PREFIX]);
		expect(
			await claims[MFA_RATE_LIMIT_PREFIX]?.({ section: mfaSection("required") } as never),
		).toBeNull();
	});

	it("registers no budget through createApp: the limiter's own limits and defaultLimit decide", async () => {
		const { handle } = await boot();
		expect(handle.components.rateLimitBudgetResolver?.get(MFA_RATE_LIMIT_PREFIX)).toBeUndefined();
	});
});

describe("mfa.rateLimit", () => {
	it("refuses the boot when it sets a budget, naming each key as removed", async () => {
		const err = await refusal({
			config: configFor("required", { rateLimit: { routes: { limit: 60, windowSeconds: 300 } } }),
		});
		expect(err.reason).toBe("config-path-relocated");
		expect(err.message).toContain("mfa.rateLimit.routes.limit was removed");
		expect(err.message).toContain("mfa.rateLimit.routes.windowSeconds was removed");
	});

	it("refuses the boot when it is set to null, naming it as removed", async () => {
		const err = await refusal({ config: configFor("required", { rateLimit: null }) });
		expect(err.reason).toBe("config-path-relocated");
		expect(err.message).toContain("mfa.rateLimit was removed");
	});

	it("refuses the boot when it is an empty block, naming it as a key the section does not know", async () => {
		const err = await refusal({ config: configFor("required", { rateLimit: {} }) });
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("mfa: has a key it does not know: rateLimit");
	});
});
