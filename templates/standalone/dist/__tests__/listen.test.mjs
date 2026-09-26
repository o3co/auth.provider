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
 * Starting the listener: one object-first `server_listening` line once the
 * socket is bound — and none for a port that was never bound.
 *
 * The line used to be a template string, `Server is running on
 * http://localhost:<port>`, which a log pipeline indexes as free text rather
 * than as an event with a port. And the standalone called Express 5's
 * `app.listen`, which hands its callback the server's `error` as well as its
 * `listening`: a callback that ignored its argument announced a server on a
 * port another process held, while the error that should have ended the
 * process was swallowed. `listen` now builds the server and wires its events
 * itself.
 */
import { createServer } from "node:http";
import express from "express";
import { afterEach, describe, expect, it } from "vitest";
import { listen } from "#/listen.mjs";
/** A logger that records what each level is handed. */
function recordingLogger() {
    const calls = [];
    const record = (level) => (...args) => {
        calls.push({ level, args });
    };
    const logger = {
        trace: record("trace"),
        debug: record("debug"),
        info: record("info"),
        warn: record("warn"),
        error: record("error"),
        fatal: record("fatal"),
        child: () => logger,
    };
    return { logger, calls };
}
const opened = [];
afterEach(async () => {
    await Promise.all(opened.splice(0).map((server) => new Promise((resolve) => server.close(() => resolve()))));
});
describe("listen", () => {
    it("says server_listening once, object-first, with the port the socket holds", async () => {
        const { logger, calls } = recordingLogger();
        const server = await listen(express(), 0, logger);
        opened.push(server);
        const { port } = server.address();
        expect(port).toBeGreaterThan(0);
        expect(calls).toEqual([{ level: "info", args: [{ port }, "server_listening"] }]);
    });
    it("logs a server error after the bind — server_error, the projection — rather than swallowing it", async () => {
        // Once the socket is bound, a later `error` (accept EMFILE) went to
        // Express 5's spent listen callback and was lost — and the one after
        // it, with no listener left, threw out of the process.
        const { logger, calls } = recordingLogger();
        const server = await listen(express(), 0, logger);
        opened.push(server);
        calls.length = 0;
        const failure = Object.assign(new Error("accept EMFILE"), { code: "EMFILE" });
        server.emit("error", failure);
        server.emit("error", failure);
        expect(calls).toEqual([
            {
                level: "error",
                args: [{ err: expect.objectContaining({ name: "Error", code: "EMFILE" }) }, "server_error"],
            },
            {
                level: "error",
                args: [{ err: expect.objectContaining({ name: "Error", code: "EMFILE" }) }, "server_error"],
            },
        ]);
        const line = calls[0]?.args[0];
        expect(line.err).not.toBeInstanceOf(Error);
    });
    it("leaves the bound server one error listener, server_error's: the bind's own is removed", async () => {
        // The listener that turns a bind failure into a rejection has done its
        // job once the socket is bound. Left attached, it would take every
        // later error beside server_error's — a callback already spent.
        const { logger } = recordingLogger();
        const server = await listen(express(), 0, logger);
        opened.push(server);
        expect(server.listenerCount("error")).toBe(1);
        // And nothing of `listen`'s own left on `listening`: an http.Server
        // keeps one there itself (its connection tracking).
        expect(server.listenerCount("listening")).toBe(createServer().listenerCount("listening"));
    });
    it("rejects with the server's error for a port already bound, and announces nothing", async () => {
        const holder = createServer();
        // Every interface, as `server.listen(port)` binds, so the two collide.
        await new Promise((resolve) => holder.listen(0, resolve));
        opened.push(holder);
        const { port } = holder.address();
        const { logger, calls } = recordingLogger();
        await expect(listen(express(), port, logger)).rejects.toMatchObject({ code: "EADDRINUSE" });
        expect(calls).toEqual([]);
    });
});
