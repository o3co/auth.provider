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
 * What the template's shared Redis connection logs when the server refuses
 * it: the real ioredis the template ships, against a TCP server that answers
 * the way Redis answers a password it no longer accepts. ioredis puts the
 * handshake it sent — `AUTH` and the password — on the error it emits, so
 * the `error` listener must log core's `loggableError` projection, never
 * the error. The logger here serialises every own property of what it is
 * handed, as a deployment's logger may.
 */
import { once } from "node:events";
import { createServer } from "node:net";
import { describe, expect, it, vi } from "vitest";
import { standaloneRedisClientsModule } from "#/modules.mjs";
/** Redis's reply to a handshake whose password it does not accept. */
const WRONGPASS = "-WRONGPASS invalid username-password pair or user is disabled.\r\n";
/** The password the deployment is configured with, and the server no longer takes. */
const STALE_PASSWORD = "stale-s3cret-redis-password";
/** A TCP server that answers everything sent to it as Redis answers a refused password. */
async function refusingRedis() {
    const sockets = new Set();
    const server = createServer((socket) => {
        sockets.add(socket);
        socket.on("close", () => sockets.delete(socket));
        socket.on("data", () => {
            socket.write(WRONGPASS);
        });
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const { port } = server.address();
    return {
        port,
        close: async () => {
            for (const socket of sockets)
                socket.destroy();
            await new Promise((resolve) => server.close(() => resolve()));
        },
    };
}
/**
 * A logger that serialises every own property of what it is handed, `cause`
 * and non-enumerable fields included. `lines` is what it wrote; its levels
 * are spies.
 */
const serialiseEverythingLogger = () => {
    const lines = [];
    const walk = (value, seen = new WeakSet()) => {
        if (typeof value !== "object" || value === null)
            return value;
        if (seen.has(value))
            return "[circular]";
        seen.add(value);
        const out = {};
        for (const key of Object.getOwnPropertyNames(value)) {
            out[key] = walk(value[key], seen);
        }
        return out;
    };
    const record = (level) => vi.fn((...args) => {
        lines.push(JSON.stringify({ level, args: walk(args) }));
    });
    const logger = {
        trace: record("trace"),
        debug: record("debug"),
        info: record("info"),
        warn: record("warn"),
        error: record("error"),
        fatal: record("fatal"),
        child: () => logger,
    };
    return { logger: logger, lines };
};
describe("standaloneRedisClientsModule: the shared connection refused by the server", () => {
    it("logs the connection's error as loggableError's projection, never the AUTH arguments ioredis puts on it", async () => {
        const redis = await refusingRedis();
        const cleanups = [];
        const lifecycleRegistrar = {
            register: (cleanup) => {
                cleanups.push(cleanup);
            },
        };
        const { logger, lines } = serialiseEverythingLogger();
        const provides = standaloneRedisClientsModule.provides;
        try {
            await provides.refreshTokenFamilyClient({
                config: {
                    refreshTokenFamilyStore: {
                        redis: { url: `redis://127.0.0.1:${redis.port}`, password: STALE_PASSWORD },
                    },
                },
                lifecycleRegistrar,
                logger,
            });
            await vi.waitFor(() => expect(logger.error).toHaveBeenCalled(), { timeout: 10_000 });
        }
        finally {
            // `io.quit()`, as `handle.dispose()` runs it.
            await Promise.all(cleanups.map((cleanup) => cleanup().catch(() => { })));
            await redis.close();
        }
        expect(logger.error).toHaveBeenCalledWith({
            err: expect.objectContaining({
                name: "ReplyError",
                detail: expect.stringMatching(/^WRONGPASS /),
                // Which command the server refused, and nothing it carried.
                command: { name: "hello" },
            }),
        }, "standalone_redis_clients_error");
        for (const line of lines)
            expect(line).not.toContain(STALE_PASSWORD);
    });
});
