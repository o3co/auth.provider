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
 * boot/__tests__/terminal-error.integration.test.mts — what the router
 * `createApp` returns answers for an error a route let through.
 *
 * The OAuth, session and WebAuthn routers parse their bodies and have no
 * error handler of their own, and no module is obliged to catch everything.
 * Only the standalone template mounted a terminal handler after the router,
 * so a composition root that mounted `handle.router` alone answered a body
 * parser's refusal, and any error that escaped a route, with Express's final
 * handler: an HTML page, with the stack outside production, where V8's JSON
 * error quotes the body it could not parse. The router now ends in core's
 * own handler.
 */

import express, { Router } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import type { BootstrapMap } from "#/boot/types.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const spyLogger = () => {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: () => logger,
	};
	return logger;
};

/** Every call on every level but `error`, which each test asserts itself. */
const otherLevels = (logger: ReturnType<typeof spyLogger>) =>
	[logger.trace, logger.debug, logger.info, logger.warn, logger.fatal].flatMap(
		(level) => level.mock.calls,
	);

/**
 * A module whose routes do what the bundled ones do — parse their own body
 * on their own path — and one that throws: a route contribution core has
 * never heard of.
 */
const routesModule = defineModule({
	name: "test:routes",
	contributes: {
		routes: [
			() => {
				const router = Router();
				router.all("/echo", express.json({ limit: 64 }), express.urlencoded({ extended: false }));
				router.post("/echo", (req, res) => {
					res.status(200).json({ received: req.body });
				});
				router.get("/item/:id", (req, res) => {
					res.status(200).json({ id: req.params.id });
				});
				router.get("/gone", () => {
					// An `http-errors` refusal that is not a body's: `expose`, 404.
					throw Object.assign(new Error("no such record: record-id-marker"), {
						status: 404,
						statusCode: 404,
						expose: true,
					});
				});
				router.get("/store-refused", () => {
					// A store's refusal carrying the HTTP status it got, not marked
					// as the client's: this server's fault.
					throw Object.assign(new Error("the Store refused this deployment's token"), {
						status: 401,
					});
				});
				router.get("/deep/*rest", () => {
					throw new Error("failed somewhere deep");
				});
				router.get("/boom", () => {
					throw Object.assign(new Error("store said: secret-in-message-marker"), {
						command: { name: "set", args: ["secret-in-args-marker"] },
					});
				});
				router.get("/half-sent", (_req, res) => {
					res.writeHead(200, { "Content-Type": "text/plain" });
					res.write("partial");
					throw new Error("failed after the headers went out");
				});
				return { id: "test:routes", mountPath: "/t", handler: router };
			},
		],
	},
});

const boot = async (logger: ReturnType<typeof spyLogger>) => {
	const handle = await createApp({
		modules: [routesModule],
		bootstrapComponents: {
			config: makeValidCoreConfig() as never,
			pathResolver: (s: string) => s,
			logger: logger as unknown as Logger,
		} satisfies Record<string, unknown> as BootstrapMap,
	});
	// The router alone: no handler of the host's after it.
	const app = express();
	app.use(handle.router);
	return { app, handle };
};

/** A body with no content in it that a parser quoted into its error. */
const MALFORMED_JSON = '{"client_secret":"body-secret-marker';

describe("createApp's router answers a body parser's refusal itself", () => {
	it.each([
		["malformed JSON", 400, "malformed_body", "application/json", MALFORMED_JSON, {}],
		[
			"a body over the route's limit",
			413,
			"body_too_large",
			"application/json",
			JSON.stringify({ pad: "x".repeat(200) }),
			{},
		],
		[
			"a charset the parser cannot decode",
			415,
			"unsupported_encoding",
			"application/json; charset=klingon",
			"{}",
			{},
		],
		[
			"a Content-Encoding the parser cannot decode",
			415,
			"unsupported_encoding",
			"application/json",
			"{}",
			{ "Content-Encoding": "br-nonsense" },
		],
	] as const)(
		"%s: %i %s in the RFC 6749 envelope, no stack, nothing logged",
		async (_name, status, description, type, body, headers) => {
			const logger = spyLogger();
			const { app, handle } = await boot(logger);

			const res = await request(app)
				.post("/t/echo")
				.set("Content-Type", type)
				.set(headers)
				.send(body);

			expect(res.status).toBe(status);
			expect(res.headers["content-type"]).toMatch(/^application\/json/);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.body).toEqual({ error: "invalid_request", error_description: description });
			expect(res.text).not.toContain("body-secret-marker");
			expect(res.text).not.toMatch(/ at /);
			// The client's own mistake, which it can send at will: not an error line.
			expect(logger.error).not.toHaveBeenCalled();
			expect(otherLevels(logger)).toEqual([]);
			await handle.dispose();
		},
	);

	it("answers a path parameter Express could not decode as 400 malformed_path, nothing logged", async () => {
		const logger = spyLogger();
		const { app, handle } = await boot(logger);

		const res = await request(app).get("/t/item/%E0%A4%A");

		expect(res.status).toBe(400);
		expect(res.headers["content-type"]).toMatch(/^application\/json/);
		expect(res.body).toEqual({ error: "invalid_request", error_description: "malformed_path" });
		expect(logger.error).not.toHaveBeenCalled();
		expect(otherLevels(logger)).toEqual([]);
		await handle.dispose();
	});

	it("keeps the status of any other refusal marked as the client's, answering it without its message", async () => {
		const logger = spyLogger();
		const { app, handle } = await boot(logger);

		const res = await request(app).get("/t/gone");

		expect(res.status).toBe(404);
		expect(res.headers["content-type"]).toMatch(/^application\/json/);
		expect(res.body).toEqual({ error: "invalid_request", error_description: "request_refused" });
		expect(res.text).not.toContain("record-id-marker");
		expect(logger.error).not.toHaveBeenCalled();
		expect(otherLevels(logger)).toEqual([]);
		await handle.dispose();
	});

	it("keeps a parsed body working", async () => {
		const logger = spyLogger();
		const { app, handle } = await boot(logger);
		const res = await request(app).post("/t/echo").send({ ok: true });
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ received: { ok: true } });
		await handle.dispose();
	});
});

describe("createApp's router answers an error that escaped a route", () => {
	it("is 500 server_error in the envelope, logged once at error with the error's projection", async () => {
		const logger = spyLogger();
		const { app, handle } = await boot(logger);

		const res = await request(app).get("/t/boom");

		expect(res.status).toBe(500);
		expect(res.headers["content-type"]).toMatch(/^application\/json/);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		expect(res.text).not.toContain("marker");
		expect(logger.error).toHaveBeenCalledTimes(1);
		const [fields, event, ...rest] = logger.error.mock.calls[0] as unknown[];
		expect(event).toBe("unhandled_request_error");
		expect(rest).toEqual([]);
		expect(fields).toEqual({
			endpoint: "/t/boom",
			err: {
				name: "Error",
				detail: "store said: secret-in-message-marker",
				command: { name: "set" },
				stack: expect.stringMatching(/^ {4}at /),
			},
		});
		expect((fields as { err: unknown }).err).not.toBeInstanceOf(Error);
		expect(JSON.stringify(logger.error.mock.calls)).not.toContain("secret-in-args-marker");
		expect(otherLevels(logger)).toEqual([]);
		await handle.dispose();
	});

	it("takes a 4xx status the error did not mark as the client's for the server's: 500, logged", async () => {
		const logger = spyLogger();
		const { app, handle } = await boot(logger);

		const res = await request(app).get("/t/store-refused");

		expect(res.status).toBe(500);
		expect(res.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				endpoint: "/t/store-refused",
				err: expect.objectContaining({ name: "Error", status: 401 }),
			},
			"unhandled_request_error",
		);
		await handle.dispose();
	});

	it("logs the path as an audit field: capped, whatever length the caller sent", async () => {
		const logger = spyLogger();
		const { app, handle } = await boot(logger);

		await request(app).get(`/t/deep/${"segment/".repeat(60)}end`);

		expect(logger.error).toHaveBeenCalledTimes(1);
		const [fields] = logger.error.mock.calls[0] as [{ endpoint: string }];
		expect(fields.endpoint).toHaveLength(200);
		expect(fields.endpoint.startsWith("/t/deep/segment/")).toBe(true);
		expect(fields.endpoint.endsWith("...")).toBe(true);
		await handle.dispose();
	});

	it("closes a response whose headers already went out, and logs it once", async () => {
		const logger = spyLogger();
		const { app, handle } = await boot(logger);

		const outcome = await request(app)
			.get("/t/half-sent")
			.then(
				(res) => ({ completed: res.status }),
				(err: unknown) => ({ failed: (err as Error).message }),
			);

		// Not rewritten into an answer it cannot be: the connection is closed.
		expect(outcome).toMatchObject({ failed: expect.any(String) });
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				endpoint: "/t/half-sent",
				headersSent: true,
				err: expect.objectContaining({
					name: "Error",
					detail: "failed after the headers went out",
				}),
			},
			"unhandled_request_error",
		);
		expect(otherLevels(logger)).toEqual([]);
		await handle.dispose();
	});

	it("leaves a request no route answered to the host, as before", async () => {
		const logger = spyLogger();
		const { handle } = await boot(logger);
		const app = express();
		app.use(handle.router);
		app.get("/host-route", (_req, res) => {
			res.status(204).end();
		});
		expect((await request(app).get("/host-route")).status).toBe(204);
		expect(logger.error).not.toHaveBeenCalled();
		await handle.dispose();
	});
});
