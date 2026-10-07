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
 * #556 — the server `request(app)` starts listens on the address supertest
 * dials, in this project's own test run.
 *
 * Unpatched, supertest starts its server with `app.listen(0)` — the
 * dual-stack wildcard `[::]:P` — and sends the request to `127.0.0.1:P`. On
 * macOS the kernel can hand out a `P` another process already holds as
 * `127.0.0.1:P`; the request then reaches that process, and if it never
 * answers the test hangs until its timeout. `vitest.supertest-loopback.mts`
 * (wired in through `setupFiles` in `vitest.config.mts`) binds the server to
 * `127.0.0.1` instead. These tests fail if that wiring is lost.
 */
import http from "node:http";
import net from "node:net";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
function helloApp() {
    const app = express();
    app.get("/hello", (_req, res) => {
        res.status(200).send("hello");
    });
    return app;
}
/** Resolves with the address `server` binds, whoever calls `listen`. */
function boundAddress(server) {
    return new Promise((resolve) => {
        server.once("listening", () => resolve(server.address()));
    });
}
describe("#556 — supertest's own server listens on the loopback address it dials", () => {
    it("binds 127.0.0.1, not the dual-stack wildcard", async () => {
        const server = http.createServer(helloApp());
        const bound = boundAddress(server);
        const res = await request(server).get("/hello");
        expect(res.status).toBe(200);
        expect(await bound).toMatchObject({ address: "127.0.0.1", family: "IPv4" });
        // supertest still closes the server it started.
        expect(server.listening).toBe(false);
    });
    it("rejects promptly with the request's own error when the request cannot be built", async () => {
        // Node refuses this header value (ERR_INVALID_CHAR) while supertest builds
        // the request. With the loopback bind that happens after the bind settles,
        // outside the promise the test awaits; the throw must still reject that
        // promise, as it does unpatched, and not become an unhandled rejection
        // that leaves the request hanging until the test timeout.
        const server = http.createServer(helloApp());
        await expect(request(server).get("/hello").set("x-test", "bad\nvalue")).rejects.toMatchObject({
            code: "ERR_INVALID_CHAR",
        });
        // The request never went out, so nothing would close the server it started.
        expect(server.listening).toBe(false);
    }, 5_000);
    it("hands the same error to an .end() callback", async () => {
        const server = http.createServer(helloApp());
        const err = await new Promise((resolve) => {
            request(server)
                .get("/hello")
                .set("x-test", "bad\nvalue")
                .end((error) => resolve(error));
        });
        expect(err).toMatchObject({ code: "ERR_INVALID_CHAR" });
    }, 5_000);
    it("serves requests an agent sends together over its one server", async () => {
        const agent = request.agent(helloApp());
        const responses = await Promise.all([agent.get("/hello"), agent.get("/hello")]);
        expect(responses.map((res) => res.status)).toEqual([200, 200]);
    });
    it("fails the request, instead of hanging on another socket, when 127.0.0.1:P is taken", async () => {
        // The collision the kernel produces by chance, produced on purpose: a
        // socket that accepts and never answers holds 127.0.0.1:P, and the
        // server supertest starts is steered onto P.
        const held = [];
        const squatter = net.createServer((socket) => {
            held.push(socket);
        });
        await new Promise((resolve) => squatter.listen(0, "127.0.0.1", resolve));
        const { port } = squatter.address();
        const server = http.createServer(helloApp());
        const listen = server.listen.bind(server);
        server.listen = (_port, ...rest) => listen(port, ...rest);
        try {
            await expect(request(server).get("/hello")).rejects.toMatchObject({
                code: "EADDRINUSE",
            });
        }
        finally {
            for (const socket of held)
                socket.destroy();
            squatter.close();
        }
    }, 5_000);
});
