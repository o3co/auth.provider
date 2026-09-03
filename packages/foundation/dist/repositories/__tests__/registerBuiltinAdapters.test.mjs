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
import { AdapterFactoryError, createAdapterFactory, } from "@o3co/auth-provider-core";
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { registerBuiltinAdapters } from "#/index.mjs";
const BASE_URL = "http://localhost:19090";
const mockUser = { id: "u1", username: "alice" };
const server = setupServer(http.post(`${BASE_URL}/auth`, async ({ request }) => {
    const body = (await request.json());
    if (body.email === "alice" && body.password === "pass") {
        return HttpResponse.json(mockUser, { status: 200 });
    }
    return new HttpResponse(null, { status: 401 });
}), http.post(`${BASE_URL}/auth/token`, async ({ request }) => {
    const body = (await request.json());
    if (body.token === "valid") {
        return HttpResponse.json(mockUser, { status: 200 });
    }
    return new HttpResponse(null, { status: 401 });
}));
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
describe("registerBuiltinAdapters", () => {
    it("registers 'http' type in userFactory", async () => {
        const userFactory = createAdapterFactory("UserRepository");
        const codeFactory = createAdapterFactory("CodeRepository");
        registerBuiltinAdapters({ userFactory, codeFactory });
        try {
            await userFactory.create({ type: "unknown" });
            throw new Error("should have thrown");
        }
        catch (err) {
            expect(err).toBeInstanceOf(AdapterFactoryError);
            const e = err;
            expect(e.reason).toBe("unknown");
            expect(e.kind).toBe("UserRepository");
            expect(e.registered).toContain("http");
        }
    });
    it("registers 'redis' type in codeFactory", async () => {
        const userFactory = createAdapterFactory("UserRepository");
        const codeFactory = createAdapterFactory("CodeRepository");
        registerBuiltinAdapters({ userFactory, codeFactory });
        try {
            await codeFactory.create({ type: "unknown" });
            throw new Error("should have thrown");
        }
        catch (err) {
            expect(err).toBeInstanceOf(AdapterFactoryError);
            const e = err;
            expect(e.reason).toBe("unknown");
            expect(e.kind).toBe("CodeRepository");
            expect(e.registered).toContain("redis");
        }
    });
    it("http builder creates a working HttpUserRepository", async () => {
        const userFactory = createAdapterFactory("UserRepository");
        const codeFactory = createAdapterFactory("CodeRepository");
        registerBuiltinAdapters({ userFactory, codeFactory });
        const repo = await userFactory.create({
            type: "http",
            authenticateUrl: `${BASE_URL}/auth`,
            authenticateByTokenUrl: `${BASE_URL}/auth/token`,
            timeout: 5000,
        });
        const user = await repo.authenticate("alice", "pass");
        expect(user).not.toBeNull();
        expect(user?.username).toBe("alice");
        const byToken = await repo.authenticateByToken("valid");
        expect(byToken).not.toBeNull();
        const invalid = await repo.authenticate("alice", "wrong");
        expect(invalid).toBeNull();
    });
    it("http builder coerces string timeout to number (env-override path)", async () => {
        const userFactory = createAdapterFactory("UserRepository");
        const codeFactory = createAdapterFactory("CodeRepository");
        registerBuiltinAdapters({ userFactory, codeFactory });
        const repo = await userFactory.create({
            type: "http",
            authenticateUrl: `${BASE_URL}/auth`,
            authenticateByTokenUrl: `${BASE_URL}/auth/token`,
            timeout: "1234", // string, as HOCON env override produces
        });
        expect(repo).toBeDefined();
        // HttpUserRepository doesn't expose timeout publicly; we verify it didn't throw
        // and works via the MSW fixture. The coercion path is internal.
        const user = await repo.authenticate("alice", "pass");
        expect(user).not.toBeNull();
    });
    it("http builder throws when authenticateUrl is missing", async () => {
        const userFactory = createAdapterFactory("UserRepository");
        const codeFactory = createAdapterFactory("CodeRepository");
        registerBuiltinAdapters({ userFactory, codeFactory });
        await expect(userFactory.create({ type: "http", timeout: 5000 })).rejects.toThrow(/authenticateUrl/);
    });
    it("redis builder throws when endpointUri is missing", async () => {
        const userFactory = createAdapterFactory("UserRepository");
        const codeFactory = createAdapterFactory("CodeRepository");
        registerBuiltinAdapters({ userFactory, codeFactory });
        await expect(codeFactory.create({ type: "redis" })).rejects.toThrow(/endpointUri/);
    });
});
