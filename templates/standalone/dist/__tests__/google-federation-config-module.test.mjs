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
import { googleFederationConfigModule } from "../modules.mjs";
const bridge = googleFederationConfigModule.provides.googleFederationConfig;
/** Runs the bridge over a `federations.google` section in the flat shape. */
function buildConfig(googleSection) {
    return bridge({ config: { federations: { google: { enabled: true, ...googleSection } } } });
}
const credentials = {
    clientId: "id",
    clientSecret: "secret",
    callbackURL: "https://auth.example.com/session/oauth/federation/google/callback",
};
describe("googleFederationConfigModule — redirect-policy plumbing (#278)", () => {
    it("forwards sessionDomain, authCallbackUrl, clientUrl and redirectAllowlist", () => {
        const out = buildConfig({
            ...credentials,
            sessionDomain: ".example.com",
            authCallbackUrl: "https://app.example.com/auth/callback",
            clientUrl: "https://app.example.com/",
            redirectAllowlist: ["https://app.example.com/dashboard"],
        });
        expect(out).toMatchObject({
            ...credentials,
            sessionDomain: ".example.com",
            authCallbackUrl: "https://app.example.com/auth/callback",
            clientUrl: "https://app.example.com/",
            redirectAllowlist: ["https://app.example.com/dashboard"],
        });
    });
    it("omits the optional fields when the operator did not configure them", () => {
        const out = buildConfig(credentials);
        expect(out).toEqual(credentials);
        expect("sessionDomain" in out).toBe(false);
        expect("authCallbackUrl" in out).toBe(false);
        expect("clientUrl" in out).toBe(false);
        expect("redirectAllowlist" in out).toBe(false);
    });
    it("rejects a redirectAllowlist that is not an array", () => {
        expect(() => buildConfig({ ...credentials, redirectAllowlist: "https://app.example.com/dashboard" })).toThrow(/redirectAllowlist/);
    });
    it("rejects a redirectAllowlist holding a non-string", () => {
        expect(() => buildConfig({ ...credentials, redirectAllowlist: [42] })).toThrow(/redirectAllowlist/);
    });
    it("rejects a non-string sessionDomain rather than forwarding it", () => {
        expect(() => buildConfig({ ...credentials, sessionDomain: 42 })).toThrow(/sessionDomain/);
    });
    it("still rejects a section missing the credentials", () => {
        expect(() => buildConfig({ clientId: "id" })).toThrow(/clientId, clientSecret, callbackURL/);
    });
    it("reads through the nested federation shape as well as the flat one", () => {
        const out = bridge({
            config: {
                federations: {
                    google: {
                        enabled: true,
                        type: "google",
                        sessionDomain: ".example.com",
                        redirectAllowlist: ["https://app.example.com/dashboard"],
                        google: credentials,
                    },
                },
            },
        });
        expect(out.sessionDomain).toBe(".example.com");
        expect(out.redirectAllowlist).toEqual(["https://app.example.com/dashboard"]);
    });
});
