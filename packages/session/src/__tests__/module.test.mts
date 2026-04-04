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
  type ModuleContext,
  type UserRepository,
} from "@o3co/auth-provider-core";
import { sessionModule } from "../module.mjs";

const mockConfig = {
  oauth: {
    jwt: { secret: "test-secret" },
    accessToken: { expiresIn: 3600 },
    refreshToken: { expiresIn: 86400 },
    grants: {},
  },
  rateLimit: {
    login: { windowMs: 60000, limit: 100 },
  },
  cors: {
    allowedOrigins: [],
  },
  session: {
    domain: null,
  },
  federations: {
    google: { enabled: false },
  },
  endpoints: {
    login: { url: "/login" },
    client: { url: "http://localhost:3001" },
    authCallback: { url: "/auth/callback" },
  },
} as unknown as AppConfig;

const makeContext = (overrides?: Partial<ModuleContext>): ModuleContext => ({
  pathResolver: (s: string) => s,
  config: mockConfig,
  keyStore: createSymmetricKeyStore("test-secret"),
  grantRegistry: new GrantRegistry(),
  router: {
    use: vi.fn().mockReturnThis(),
  } as unknown as Router,
  ...overrides,
});

describe("sessionModule", () => {
  it("has name 'session'", () => {
    const module = sessionModule({
      userRepository: {} as UserRepository,
    });
    expect(module.name).toBe("session");
  });

  it("mounts /session routes on context.router", async () => {
    const routerMock = {
      use: vi.fn().mockReturnThis(),
    } as unknown as Router;
    const ctx = makeContext({ router: routerMock });
    const module = sessionModule({
      userRepository: {
        authenticate: vi.fn(),
        authenticateByToken: vi.fn(),
      } as unknown as UserRepository,
    });

    await module.init(ctx);

    // Should mount session and federation routes under /session
    const calls = (routerMock.use as ReturnType<typeof vi.fn>).mock.calls;
    const sessionCalls = calls.filter(
      (call: unknown[]) => call[0] === "/session",
    );
    expect(sessionCalls.length).toBeGreaterThanOrEqual(1);
  });
});
