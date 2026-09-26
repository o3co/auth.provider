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
 * What the template's own logger writes for a projected error — the line on
 * stdout, from `createAppLogger` in a process of its own, as the service
 * writes it. Every field of core's `loggableError` projection must reach
 * it, at every level of the cause chain: the logger's `err` serializer must
 * not take the projection for an Error and fold its causes into one message.
 */
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
const templateRoot = fileURLToPath(new URL("../..", import.meta.url));
const tsxCli = createRequire(import.meta.url).resolve("tsx/cli");
/**
 * A request failure caused by a Store failure caused by a parse failure,
 * logged through `createAppLogger` in a child process; the line it wrote.
 */
const SCRIPT = `
const { createAppLogger } = await import("./src/logger.mts");
const { loggableError } = await import("@o3co/auth-provider-core");
let parse;
try { JSON.parse('{"a":1,'); } catch (err) { parse = err; }
const store = Object.assign(new Error("the Store could not be read", { cause: parse }), {
	name: "StoreTransportError", code: "ECONNREFUSED", reason: "unreachable", storeStatus: 503,
});
const failed = Object.assign(new Error("request failed", { cause: store }), {
	type: "upstream.failed", status: 502,
});
createAppLogger({ logging: { level: "info" } }).error({ err: loggableError(failed) }, "unhandled_request_error");
`;
describe("createAppLogger writes a projected error whole", () => {
    it("keeps every field of every level of the cause chain on the line", () => {
        const stdout = execFileSync(process.execPath, [tsxCli, "--input-type=module", "--eval", SCRIPT], { cwd: templateRoot, encoding: "utf8" });
        const line = JSON.parse(stdout.trim().split("\n").at(-1) ?? "{}");
        expect(line.msg).toBe("unhandled_request_error");
        expect(line.err).toMatchObject({
            name: "Error",
            type: "upstream.failed",
            status: 502,
            cause: {
                name: "StoreTransportError",
                code: "ECONNREFUSED",
                reason: "unreachable",
                storeStatus: 503,
                cause: { name: "SyntaxError", position: 7 },
            },
        });
    });
});
