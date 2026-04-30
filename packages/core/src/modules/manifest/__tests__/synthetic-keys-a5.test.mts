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

test("SYNTHETIC_COMPONENT_KEYS has 4 members after A5", () => {
	expect(SYNTHETIC_COMPONENT_KEYS.size).toBe(4);
});

test("SYNTHETIC_COMPONENT_KEYS includes federationRedirectPolicyResolver", () => {
	expect(SYNTHETIC_COMPONENT_KEYS.has("federationRedirectPolicyResolver")).toBe(true);
});

test("SYNTHETIC_COMPONENT_KEYS still includes the original 3 keys", () => {
	expect(SYNTHETIC_COMPONENT_KEYS.has("federationProviders")).toBe(true);
	expect(SYNTHETIC_COMPONENT_KEYS.has("tokenExchangeValidatorResolver")).toBe(true);
	expect(SYNTHETIC_COMPONENT_KEYS.has("grantHandlerResolver")).toBe(true);
});
