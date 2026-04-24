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
import { ExchangeTokenValidatorRegistry } from "#/validator/registry.mjs";
import type { ExchangeTokenValidator } from "#/validator/types.mjs";

const stubValidator = (tokenType: string): ExchangeTokenValidator => ({
  tokenType,
  async validate() {
    return null;
  },
});

describe("ExchangeTokenValidatorRegistry", () => {
  it("returns undefined for unregistered token type", () => {
    const registry = new ExchangeTokenValidatorRegistry();
    expect(registry.get("urn:ietf:params:oauth:token-type:access_token")).toBeUndefined();
  });

  it("returns the registered validator by tokenType", () => {
    const registry = new ExchangeTokenValidatorRegistry();
    const v = stubValidator("urn:ietf:params:oauth:token-type:access_token");
    registry.register("urn:ietf:params:oauth:token-type:access_token", v);
    expect(registry.get("urn:ietf:params:oauth:token-type:access_token")).toBe(v);
  });

  it("overwrites an existing registration on re-register", () => {
    const registry = new ExchangeTokenValidatorRegistry();
    const v1 = stubValidator("urn:ietf:params:oauth:token-type:access_token");
    const v2 = stubValidator("urn:ietf:params:oauth:token-type:access_token");
    registry.register("urn:ietf:params:oauth:token-type:access_token", v1);
    registry.register("urn:ietf:params:oauth:token-type:access_token", v2);
    expect(registry.get("urn:ietf:params:oauth:token-type:access_token")).toBe(v2);
  });
});
