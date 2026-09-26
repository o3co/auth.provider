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
 * The template's composition, booted through core's `createApp` and mounted
 * with no terminal handler of the template's after it — the router alone, as
 * a composition root that copies nothing of `app.mts` mounts it.
 *
 * The OAuth and session routers parse their own bodies and have no error
 * handler: a body parser's refusal on `/oauth/token`, `/oauth/introspect` or
 * `/session/login`, and any error a route let through, went on to whatever
 * the host had after the router. Only `app.mts` had a handler there, so any
 * other host answered with Express's final handler — an HTML page, with the
 * stack outside production, where V8's JSON error quotes the body it could
 * not parse. The router core returns now answers them itself.
 */
import { defineModule } from "@o3co/auth-provider-core";
import { Router } from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { basic, compose, JSON_TYPE, KIB, M2M, padJson, } from "./all-modules-composition.fixture.mjs";
let current;
afterEach(async () => {
    await current?.handle.dispose();
    current = undefined;
});
/** A route that lets an error through, contributed as a deployment adds one. */
const throwingRouteModule = defineModule({
    name: "test:throwing-route",
    contributes: {
        routes: [
            () => {
                const router = Router();
                router.get("/", () => {
                    throw new Error("a store said something: escaped-error-marker");
                });
                return { id: "test:throwing-route", mountPath: "/throws", handler: router };
            },
        ],
    },
});
/** The composition, the router alone mounted. */
const boot = async () => {
    current = await compose({
        terminalErrorHandler: false,
        extraModules: () => [throwingRouteModule],
    });
    return current;
};
/** The routes that parse a body, and what each needs to reach its parser. */
const PARSING_ROUTES = [
    ["/oauth/token", { authorization: basic(M2M) }],
    ["/oauth/introspect", { authorization: basic(M2M) }],
    ["/session/login", {}],
];
const errorLines = (c) => c.logger.lines.filter((line) => line.level === "error");
describe("the composed router, mounted alone, answers a body parser's refusal", () => {
    it.each(PARSING_ROUTES)("%s: malformed JSON is 400 in the envelope, nothing logged", async (path, headers) => {
        const c = await boot();
        const res = await request(c.app)
            .post(path)
            .set(headers)
            .set("Content-Type", JSON_TYPE)
            .send('{"password":"body-secret-marker');
        expect(res.status).toBe(400);
        expect(res.headers["content-type"]).toMatch(/^application\/json/);
        expect(res.body).toEqual({ error: "invalid_request", error_description: "malformed_body" });
        expect(res.text).not.toContain("body-secret-marker");
        expect(res.text).not.toMatch(/ at /);
        expect(errorLines(c)).toEqual([]);
    });
    it.each(PARSING_ROUTES)("%s: a body over the parser's limit is 413 in the envelope, nothing logged", async (path, headers) => {
        const c = await boot();
        const res = await request(c.app)
            .post(path)
            .set(headers)
            .set("Content-Type", JSON_TYPE)
            .send(padJson(200 * KIB));
        expect(res.status).toBe(413);
        expect(res.headers["content-type"]).toMatch(/^application\/json/);
        expect(res.body).toEqual({ error: "invalid_request", error_description: "body_too_large" });
        expect(errorLines(c)).toEqual([]);
    });
});
describe("the composed router, mounted alone, answers an error a route let through", () => {
    it("is 500 server_error in the envelope, logged once at error", async () => {
        const c = await boot();
        const res = await request(c.app).get("/throws");
        expect(res.status).toBe(500);
        expect(res.headers["content-type"]).toMatch(/^application\/json/);
        expect(res.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
        expect(res.text).not.toContain("escaped-error-marker");
        expect(errorLines(c)).toEqual([
            {
                level: "error",
                args: [
                    {
                        endpoint: "/throws",
                        err: expect.objectContaining({
                            name: "Error",
                            detail: "a store said something: escaped-error-marker",
                        }),
                    },
                    "unhandled_request_error",
                ],
            },
        ]);
    });
});
