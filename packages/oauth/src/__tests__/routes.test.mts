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
import { describe, expect, it, vi } from "vitest";
import type { Router } from "express";
import {
  GrantRegistry,
  createSymmetricKeyStore,
  type AppConfig,
  type ClientRepository,
  type CodeRepository,
} from "@o3co/auth-provider-core";
import { createOAuthRouter } from "../routes.mjs";
import type { PassportStatic } from "passport";

const mockConfig = {
  rateLimit: {
    token: { windowMs: 60000, limit: 100 },
    authorize: { windowMs: 60000, limit: 100 },
  },
  endpoints: {
    login: { url: "/login" },
  },
} as unknown as AppConfig;

const mockExpress = {
  Router: () =>
    ({
      use: vi.fn().mockReturnThis(),
      get: vi.fn().mockReturnThis(),
      post: vi.fn().mockReturnThis(),
    }) as unknown as Router,
  json: () => vi.fn(),
  urlencoded: () => vi.fn(),
};

describe("createOAuthRouter", () => {
  it("returns a router", async () => {
    const mockPassport = {
      authenticate: vi.fn().mockReturnValue(vi.fn()),
    } as unknown as PassportStatic;

    const result = await createOAuthRouter(mockExpress, {
      passport: mockPassport,
      registry: new GrantRegistry(),
      config: mockConfig,
      clientRepository: {} as ClientRepository,
      codeRepository: {} as CodeRepository,
      keyStore: createSymmetricKeyStore("test-secret"),
    });

    expect(result.router).toBeDefined();
  });
});
