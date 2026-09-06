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
 * Issue #407 — scaffold hardening from the v0.10.0 release-cut audit.
 *
 * These pin the parts of the scaffold that are checkable from inside the
 * repository. The scaffold is the artifact an operator actually deploys, and
 * every one of these was invisible until someone read the file: the container
 * install losing an allowlist, the dev compose dialling a Redis that is not
 * there, and one `git add .` committing the signing key.
 */
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
const standaloneDir = fileURLToPath(new URL("../..", import.meta.url));
const read = (rel) => readFileSync(`${standaloneDir}${rel}`, "utf8");
describe("#407 — the Dockerfile installs with everything pnpm needs", () => {
    it("copies pnpm-workspace.yaml into the deps stage", () => {
        // `create-auth-provider` generates it to carry the bcrypt
        // `onlyBuiltDependencies` allowlist, because pnpm >= 10.29 reads that
        // setting ONLY from this file — in single-package projects too (#360).
        // A deps stage that copies `package.json` and the lockfile but not this
        // runs allowlist-less, which re-creates #360 the day an alpine prebuild
        // is missing and bcrypt has to compile.
        const dockerfile = read("/Dockerfile");
        const depsStage = dockerfile.slice(dockerfile.indexOf("FROM node-base AS deps"), dockerfile.indexOf("FROM", dockerfile.indexOf("FROM node-base AS deps") + 1));
        // Matched as a COPY instruction, not as a substring of the stage: the
        // comment above that COPY names the file too, so a substring check
        // would keep passing if the instruction regressed and the comment
        // stayed — which is the failure this test exists to catch.
        const copyLines = depsStage
            .split("\n")
            .filter((line) => /^COPY\b/.test(line.trim()) && !line.trim().startsWith("#"));
        expect(copyLines.some((line) => /\bpnpm-workspace\.yaml\b/.test(line))).toBe(true);
    });
});
describe("#407 — the dev compose can reach every Redis it configures", () => {
    it("sets every *_REDIS_URL the template config reads", () => {
        // The template's application.conf substitutes several Redis URLs, each
        // defaulting to `redis://localhost:6379` — which inside the container is
        // the container itself. `.env.example` is what the compose file loads,
        // so a URL missing from it is a boot that dials nothing.
        const conf = read("/config/application.conf");
        const declared = [...conf.matchAll(/\$\{\?([A-Z0-9_]*REDIS_URL)\}/g)].map((m) => m[1]);
        expect(declared.length).toBeGreaterThan(0);
        const env = read("/.env.example");
        const missing = [...new Set(declared)].filter((name) => !new RegExp(`^${name}=`, "m").test(env));
        expect(missing).toEqual([]);
    });
});
describe("#407 — the scaffold does not invite committing its own secrets", () => {
    it("ships a .gitignore", () => {
        // Without one, the first `git add .` in a scaffolded project commits
        // `.env` and `jwt-private.pem` — both of which the README tells the
        // operator to create right there.
        expect(existsSync(`${standaloneDir}/.gitignore`)).toBe(true);
    });
    it("ignores the files the scaffold's own setup steps create", () => {
        const ignored = read("/.gitignore");
        for (const pattern of [".env", "*.pem", "node_modules", "dist"]) {
            expect(ignored).toContain(pattern);
        }
    });
    it("keeps .env.example tracked — it is the documentation", () => {
        // A bare `.env*` would take the example with it, which is the mistake
        // this pins against.
        expect(read("/.gitignore")).toMatch(/^!\.env\.example$/m);
    });
});
describe("#407 — the production compose matches the topology it documents", () => {
    it("does not publish the app port on every interface", () => {
        // The README says to keep `/metrics` off the public listener and the
        // file assumes TLS is terminated in front, so a bare "3000:3000"
        // contradicts both — it binds 0.0.0.0 on the host.
        const compose = read("/docker-compose.production.yml");
        expect(compose).not.toMatch(/^\s*-\s*"3000:3000"\s*$/m);
        expect(compose).toMatch(/127\.0\.0\.1:3000:3000/);
    });
});
describe("#407 — the two READMEs agree on security advice", () => {
    it("does not recommend HTTP_TRUST_PROXY=true in the Japanese README", () => {
        // #292 made `trust proxy` a CIDR/hop policy precisely because `true`
        // means "believe the leftmost forwarded entry from whoever opened the
        // connection". The English README warns against it; the Japanese one
        // still recommended it, so the two disagreed on which is safe.
        expect(read("/README.ja.md")).not.toMatch(/HTTP_TRUST_PROXY=true/);
    });
});
