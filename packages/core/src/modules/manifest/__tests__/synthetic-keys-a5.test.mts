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
import { expect, test } from "vitest";
import { SYNTHETIC_COMPONENT_KEYS } from "../synthetic-keys.mjs";

test("SYNTHETIC_COMPONENT_KEYS has 11 members", () => {
	// 4 federation and grant keys + lifecycleRegistrar + readinessRegistrar +
	// mfaFactorResolver (the MFA ADR's D3) + sessionRequirementResolver (the
	// session-admission ADR's D3) + rateLimitBudgetResolver + deploymentMode +
	// tokenBindingSettings = 11.
	expect(SYNTHETIC_COMPONENT_KEYS.size).toBe(11);
});

test("SYNTHETIC_COMPONENT_KEYS includes tokenBindingSettings", () => {
	// Core fills it from the configuration's core.tokenBinding: a module or
	// host that set it would be a second source of the token-binding settings,
	// beside the one boot's dispatch policy reads.
	expect(SYNTHETIC_COMPONENT_KEYS.has("tokenBindingSettings")).toBe(true);
});

test("SYNTHETIC_COMPONENT_KEYS includes deploymentMode", () => {
	// Core fills it from the configuration's core.deployment.mode: a module or host
	// that set it would be a second statement of the replica count, beside the
	// one the replica-safety guard reads.
	expect(SYNTHETIC_COMPONENT_KEYS.has("deploymentMode")).toBe(true);
});

test("SYNTHETIC_COMPONENT_KEYS includes readinessRegistrar", () => {
	// Reserved for the same reason as lifecycleRegistrar: a consumer-supplied
	// registrar would collect probes the planner never reads.
	expect(SYNTHETIC_COMPONENT_KEYS.has("readinessRegistrar")).toBe(true);
});

test("SYNTHETIC_COMPONENT_KEYS includes federationRedirectPolicyResolver", () => {
	expect(SYNTHETIC_COMPONENT_KEYS.has("federationRedirectPolicyResolver")).toBe(true);
});

test("SYNTHETIC_COMPONENT_KEYS still includes the original 3 keys", () => {
	expect(SYNTHETIC_COMPONENT_KEYS.has("federationProviders")).toBe(true);
	expect(SYNTHETIC_COMPONENT_KEYS.has("tokenExchangeValidatorResolver")).toBe(true);
	expect(SYNTHETIC_COMPONENT_KEYS.has("grantHandlerResolver")).toBe(true);
});

test("SYNTHETIC_COMPONENT_KEYS includes lifecycleRegistrar", () => {
	// The boot planner owns the LifecycleRegistrar slot. Reserved so a consumer
	// can't supply their own via bootstrapComponents/overrideComponents while
	// the planner silently drains its own instance.
	expect(SYNTHETIC_COMPONENT_KEYS.has("lifecycleRegistrar")).toBe(true);
});
