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
 * `oauth.accessToken.expiresIn` / OAUTH_ACCESS_TOKEN_EXPIRES_IN is a deprecated
 * alias of `defaultExpiresIn`, and the composition says so once — the OR-9
 * shape `repositories.code.type` already has.
 *
 * The line has to be exact in both directions. Core's `reference.conf` keeps
 * the shipped lifetime on the deprecated key, so "the alias supplied the
 * default" describes every deployment that set nothing; warning on that would
 * train operators to ignore the line. Only an override of the old key is
 * something to move.
 */
import { fileURLToPath } from "node:url";
import { AppConfigSchema } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildModules } from "../buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";
const configDir = fileURLToPath(new URL("../../config", import.meta.url));
const REQUIRED_ENV = {
    OAUTH_JWT_SECRET: "access-token-alias.at-least-32-bytes.ok",
    OAUTH_JWT_ISSUER: "https://auth.test",
    SESSION_SECRET: "access-token-alias-session.at-least-32-bytes.ok",
};
/** The shipped layers, resolved the way `app.mts` resolves them. */
function loadShipped(env = {}) {
    const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "development");
    const resolvedEnv = { ...REQUIRED_ENV, ...env };
    return validate(parseFile(envConfPath, { env: resolvedEnv })
        .withFallback(parseFile(applicationConfPath, { env: resolvedEnv }))
        .withFallback(parseFile(resolveLibraryReferenceConfPath(), { env: resolvedEnv })), AppConfigSchema);
}
/** Every console warning `buildModules` emits about the deprecated key. */
function aliasWarnings(config) {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => { });
    buildModules(config);
    return warn.mock.calls
        .map((call) => String(call[0]))
        .filter((message) => message.includes("oauth.accessToken.expiresIn"));
}
describe("the deprecated access-token lifetime alias", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });
    it("says nothing for a deployment that sets no lifetime at all", () => {
        // Also what keeps the template's idea of "the shipped value" honest: it
        // is measured against core's real `reference.conf`, so a change to the
        // shipped literal fails here rather than warning every deployment.
        expect(aliasWarnings(loadShipped())).toEqual([]);
    });
    it("says nothing for a deployment on the new variable", () => {
        expect(aliasWarnings(loadShipped({ OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN: "900" }))).toEqual([]);
    });
    it("warns once when OAUTH_ACCESS_TOKEN_EXPIRES_IN still decides the default", () => {
        const warnings = aliasWarnings(loadShipped({ OAUTH_ACCESS_TOKEN_EXPIRES_IN: "900" }));
        expect(warnings).toHaveLength(1);
        expect(warnings[0]).toMatch(/deprecated/);
        expect(warnings[0]).toMatch(/oauth\.accessToken\.defaultExpiresIn/);
        expect(warnings[0]).toMatch(/OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN/);
    });
    it("warns for a hand-built configuration that overrides only the old key", () => {
        const config = loadShipped();
        expect(aliasWarnings({
            ...config,
            oauth: { ...config.oauth, accessToken: { expiresIn: 900 } },
        })).toHaveLength(1);
    });
});
