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
 * The MFA routes' budget the template ships: every `/session/mfa` POST is
 * limited under the prefix `mfa` by the wired limiter alone, and the
 * template's own `reference.conf` gives both limiters `limits.mfa`, 60
 * requests per 300 s. Followed through both configuration phases and
 * `createApp` to the limiter each module builds, in every environment the
 * template ships a file for.
 */
import { fileURLToPath } from "node:url";
import { createApp, defineModule, memoryRateLimiterModule, } from "@o3co/auth-provider-core";
import { redisRateLimiterModule } from "@o3co/auth-provider-redis";
import { afterEach, describe, expect, it } from "vitest";
import { readOwnLayers, readSwitches, resolveConfigPaths, resolveForBoot } from "../configPath.mjs";
import { loggingModule } from "../modules.mjs";
const configDir = fileURLToPath(new URL("../../config", import.meta.url));
/** The secrets `application.conf` substitutes: test-only values past the entropy floor. */
const SECRETS = {
    KEY_STORE_LOCAL_SECRET: "test-secret-mfa-routes-budget.at-least-32-bytes.ok",
    OAUTH_JWT_ISSUER: "https://auth.test",
    SESSION_STORE_SECRET: "test-session-secret-mfa-routes-budget.at-least-32-bytes.ok",
    MFA_MODE: "off",
};
/** The windows, in seconds, the Redis limiter asked its client to count over. */
const windows = [];
/** The limiter a consumer of the slot is handed, as the MFA routes are. */
let consumed;
const consumerModule = defineModule({
    name: "test:rate-limiter-consumer",
    requires: ["rateLimiter"],
    contributes: {
        grantMiddleware: [
            ({ rateLimiter }) => {
                consumed = rateLimiter;
                return null;
            },
        ],
    },
});
const handles = [];
afterEach(async () => {
    await Promise.all(handles.splice(0).map((handle) => handle.dispose()));
    consumed = undefined;
    windows.splice(0);
});
/** The shipped configuration for `environment`, booted with the limiter `adapter` selects. */
async function shippedLimiter(environment, adapter) {
    const env = { ...SECRETS, ADAPTERS_RATE_LIMITER: adapter };
    const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, environment);
    const own = readOwnLayers([envConfPath, applicationConfPath], { env });
    const switches = readSwitches(own);
    expect(switches.adapters.rateLimiter).toBe(adapter);
    const limiterModule = adapter === "redis" ? redisRateLimiterModule : memoryRateLimiterModule;
    const modules = [limiterModule, consumerModule];
    const handle = await createApp({
        modules,
        bootstrapComponents: {
            config: resolveForBoot(own, [...modules, loggingModule], switches),
            pathResolver: (s) => s,
            // Counts one request per key, the way an untouched Redis counter would.
            rateLimiterClient: {
                incrementWithTtl: async (_key, windowSeconds) => {
                    windows.push(windowSeconds);
                    return 1;
                },
            },
        },
    });
    handles.push(handle);
    if (consumed === undefined)
        throw new Error("the boot handed no consumer the limiter");
    return consumed;
}
describe("the MFA routes' budget the template ships", () => {
    it.each([
        ["development", "memory"],
        ["development", "redis"],
        ["production", "memory"],
        ["production", "redis"],
    ])("is 60 per 300 s under %s on the %s limiter", async (environment, adapter) => {
        const limiter = await shippedLimiter(environment, adapter);
        const before = Date.now();
        const decision = await limiter.check("mfa:ip:203.0.113.7", { ip: "203.0.113.7" });
        expect(decision.allowed).toBe(true);
        expect(decision.limit).toBe(60);
        const windowSeconds = adapter === "redis"
            ? windows[0]
            : Math.round(((decision.resetAt?.getTime() ?? 0) - before) / 1000);
        expect(windowSeconds).toBe(300);
    });
});
