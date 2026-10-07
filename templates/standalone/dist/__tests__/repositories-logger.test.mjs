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
 * The repositories module builds its user repository with the composition's
 * logger: the yaml user builder's `user_repository_in_memory` line reaches the
 * `logger` bootstrap component (the template's pino logger, at its level),
 * not the console.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createApp, defineModule, } from "@o3co/auth-provider-core";
import { CORE_RELOCATIONS, makeValidCoreConfig, renamedVariableCaptures, } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { repositoriesModuleFor } from "../modules.mjs";
const spyLogger = () => {
    const logger = {
        trace: vi.fn(),
        debug: vi.fn(),
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
        fatal: vi.fn(),
        child: vi.fn(),
    };
    logger.child.mockReturnValue(logger);
    return logger;
};
describe("the repositories module's user repository", () => {
    let dir;
    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), "repositories-logger-"));
    });
    afterEach(() => {
        fs.rmSync(dir, { recursive: true, force: true });
        vi.restoreAllMocks();
    });
    it("warns user_repository_in_memory on the composition's logger, built through createApp, and not on the console", async () => {
        const usersPath = path.join(dir, "users.yaml");
        fs.writeFileSync(usersPath, 'alice:\n  password: "plainpass"\n');
        const clientsPath = path.join(dir, "clients.yaml");
        fs.writeFileSync(clientsPath, "");
        const consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => { });
        const logger = spyLogger();
        let built;
        const reader = defineModule({
            name: "test:user-repository-reader",
            requires: ["userRepository"],
            provides: {
                userRepositoryRead: ({ userRepository }) => {
                    built = userRepository;
                    return true;
                },
            },
            lifecycle: { userRepositoryRead: { eager: true } },
        });
        const repositories = repositoriesModuleFor({ client: "yaml", user: "yaml" });
        const handle = await createApp({
            modules: [repositories, reader],
            bootstrapComponents: {
                config: {
                    ...makeValidCoreConfig(),
                    repositories: {
                        client: { yaml: { path: clientsPath } },
                        user: { yaml: { path: usersPath }, http: {} },
                    },
                    // What a resolution with none of the renamed variables set captures.
                    "renamed-variables": renamedVariableCaptures({
                        modules: [repositories],
                        core: CORE_RELOCATIONS,
                        env: {},
                    }),
                },
                pathResolver: (p) => p,
                logger: logger,
            },
        });
        try {
            expect((await built?.authenticate("alice", "plainpass"))?.username).toBe("alice");
            expect(logger.warn.mock.calls.filter(([, event]) => event === "user_repository_in_memory")).toEqual([[{ store: "userRepository", adapter: "yaml" }, "user_repository_in_memory"]]);
            expect(consoleWarn.mock.calls.filter((args) => args.includes("user_repository_in_memory"))).toEqual([]);
        }
        finally {
            await handle.dispose();
        }
    });
});
