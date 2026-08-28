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
import type { Logger } from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createTerminalErrorHandler } from "../terminalError.mjs";

const makeLogger = () => {
	const error = vi.fn();
	const logger = {
		error,
		warn: vi.fn(),
		info: vi.fn(),
		debug: vi.fn(),
	} as unknown as Logger;
	return { logger, error };
};

const makeApp = (logger: Logger) => {
	const app = express();
	app.use(express.json());
	app.post("/echo", (_req, res) => {
		res.status(200).json({ ok: true });
	});
	app.get("/boom", () => {
		throw new Error("route exploded");
	});
	app.use(createTerminalErrorHandler(logger));
	return app;
};

describe("terminal error handler (#293 item 8)", () => {
	it("answers malformed JSON with the client's 400 in the shared envelope, not Express's HTML page", async () => {
		const { logger, error } = makeLogger();
		const res = await request(makeApp(logger))
			.post("/echo")
			.set("Content-Type", "application/json")
			.send("{not json");

		expect(res.status).toBe(400);
		expect(res.headers["content-type"]).toContain("application/json");
		expect(res.body.error).toBe("invalid_request");
		// The client's malformed body is not a server error worth an error line.
		expect(error).not.toHaveBeenCalled();
	});

	it("keeps the body parser's own status for an over-limit body (413)", async () => {
		const { logger } = makeLogger();
		const app = express();
		app.use(express.json({ limit: 16 }));
		app.post("/echo", (_req, res) => {
			res.status(200).json({ ok: true });
		});
		app.use(createTerminalErrorHandler(logger));

		const res = await request(app)
			.post("/echo")
			.set("Content-Type", "application/json")
			.send(JSON.stringify({ pad: "x".repeat(64) }));

		expect(res.status).toBe(413);
		expect(res.body.error).toBe("invalid_request");
	});

	it("answers an unexpected route throw with 500 server_error and logs it structurally", async () => {
		const { logger, error } = makeLogger();
		const res = await request(makeApp(logger)).get("/boom");

		expect(res.status).toBe(500);
		expect(res.body).toEqual({
			error: "server_error",
			error_description: "Internal server error",
		});
		// No stack trace on the wire — the envelope is the whole body.
		expect(JSON.stringify(res.body)).not.toContain("route exploded");
		expect(error).toHaveBeenCalledWith(
			expect.objectContaining({ endpoint: "/boom" }),
			"unhandled_request_error",
		);
	});
});
