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
 * The host's own routes — liveness, readiness, the metrics scrape — mounted
 * as the process mounts them (`mountRoutes`), and what an error one of them
 * lets through is answered with.
 *
 * The composed router answers its own errors with core's terminal handler.
 * The host's routes sat in front of a handler of the template's own, which
 * answered in other words ("Internal server error"), took any 4xx `status`
 * for the client's mistake and answered it as one, handed an error on to
 * Express once the headers were out (whose final handler prints the stack),
 * and logged the path as it arrived. Core's handler is now the one after
 * them too, so a deployment answers every route's error the same way.
 */

import type { Logger, ReadinessProbe } from "@o3co/auth-provider-core";
import express, { Router } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createMetrics } from "#/metrics.mjs";
import { mountRoutes } from "#/routes.mjs";

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

/** A probe that breaks its own contract: reading its `name` throws. */
const probeWhoseNameThrows = (thrown: Error): ReadinessProbe =>
	({
		get name(): string {
			throw thrown;
		},
		check: async () => undefined,
	}) as ReadinessProbe;

const host = (probes: readonly ReadinessProbe[]) => {
	const logger = spyLogger();
	const app = express();
	mountRoutes(app, {
		router: Router(),
		probes,
		readinessTimeoutMs: 1_000,
		metrics: createMetrics(),
		logger: logger as unknown as Logger,
	});
	return { app, logger };
};

/** Every call on a level other than `error`. */
const otherLevels = (logger: ReturnType<typeof spyLogger>) =>
	[logger.trace, logger.debug, logger.info, logger.warn, logger.fatal].flatMap(
		(level) => level.mock.calls,
	);

describe("the host's routes, mounted as the process mounts them", () => {
	it("/_healthcheck answers 200, and nothing is logged", async () => {
		const { app, logger } = host([]);
		const res = await request(app).get("/_healthcheck");
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ status: "ok" });
		expect(logger.error).not.toHaveBeenCalled();
		expect(otherLevels(logger)).toEqual([]);
	});

	it.each(["/readyz", "/metrics"])(
		"%s: an error it lets through is 500 server_error in the envelope, no-store, logged once with its projection",
		async (path) => {
			const { app, logger } = host([
				probeWhoseNameThrows(new Error("probe registry at internal-host-marker is gone")),
			]);

			const res = await request(app).get(path);

			expect(res.status).toBe(500);
			expect(res.headers["content-type"]).toMatch(/^application\/json/);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
			expect(res.text).not.toContain("internal-host-marker");
			expect(logger.error).toHaveBeenCalledTimes(1);
			const [fields, event, ...rest] = logger.error.mock.calls[0] as unknown[];
			expect(event).toBe("unhandled_request_error");
			expect(rest).toEqual([]);
			expect(fields).toEqual({
				endpoint: path,
				err: expect.objectContaining({
					name: "Error",
					detail: "probe registry at internal-host-marker is gone",
				}),
			});
			expect((fields as { err: unknown }).err).not.toBeInstanceOf(Error);
			expect(otherLevels(logger)).toEqual([]);
		},
	);

	it("takes a 4xx status an error did not mark as the client's for the server's: 500, logged", async () => {
		// A store's or a library's error can carry an HTTP status of its own —
		// the answer it got — which is not this server's answer to the client.
		const { app, logger } = host([
			probeWhoseNameThrows(
				Object.assign(new Error("the probe registry refused this deployment"), { status: 403 }),
			),
		]);

		const res = await request(app).get("/readyz");

		expect(res.status).toBe(500);
		expect(res.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				endpoint: "/readyz",
				err: expect.objectContaining({ name: "Error", status: 403 }),
			},
			"unhandled_request_error",
		);
	});
});
