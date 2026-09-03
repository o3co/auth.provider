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
import { createSymmetricKeyStore, GrantRegistry, } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";
const mockConfig = {
    endpoints: {
        login: { url: "/login" },
    },
};
const mockExpress = {
    Router: () => ({
        use: vi.fn().mockReturnThis(),
        get: vi.fn().mockReturnThis(),
        post: vi.fn().mockReturnThis(),
    }),
    json: () => vi.fn(),
    urlencoded: () => vi.fn(),
};
describe("createOAuthRouter", () => {
    it("returns a router", async () => {
        const result = await createOAuthRouter(mockExpress, {
            registry: new GrantRegistry(),
            config: mockConfig,
            clientRepository: {},
            codeRepository: {},
            keyStore: createSymmetricKeyStore("test-secret"),
        });
        expect(result.router).toBeDefined();
    });
    it("applies rate limit middleware to POST /introspect", async () => {
        const postCalls = [];
        const router = {
            use: vi.fn().mockReturnThis(),
            get: vi.fn().mockReturnThis(),
            post: vi.fn((...args) => {
                postCalls.push(args);
                return router;
            }),
        };
        const trackingExpress = {
            Router: () => router,
            json: () => vi.fn(),
            urlencoded: () => vi.fn(),
        };
        await createOAuthRouter(trackingExpress, {
            registry: new GrantRegistry(),
            config: mockConfig,
            clientRepository: {},
            codeRepository: {},
            keyStore: createSymmetricKeyStore("test-secret"),
        });
        // Find the /introspect POST registration
        const introspectCall = postCalls.find((args) => args[0] === "/introspect");
        expect(introspectCall).toBeDefined();
        if (!introspectCall)
            return;
        // Should have at least 3 args: path, rate-limit middleware, auth middleware, handler
        // (path + tokenRateLimit + authMiddleware + handler = 4 args minimum)
        expect(introspectCall.length).toBeGreaterThanOrEqual(3);
        // The second arg (index 1) is the rate-limit middleware — it must be a function
        expect(typeof introspectCall[1]).toBe("function");
    });
});
