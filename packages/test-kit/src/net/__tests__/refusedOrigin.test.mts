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
 * A refused connection, for a test that needs one: an origin nothing listens
 * on, the same in every test file, so a server another file starts beside it
 * is never handed its port.
 */

import { createServer } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { refusedOrigin } from "#/index.mjs";
import { assertConnectionRefused } from "#/net/refusedOrigin.mjs";

const servers: ReturnType<typeof createServer>[] = [];

afterEach(async () => {
	await Promise.all(
		servers
			.splice(0)
			.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
	);
});

describe("refusedOrigin", () => {
	it("is a loopback origin a fetch to which is refused", async () => {
		const origin = await refusedOrigin();
		expect(new URL(origin).hostname).toBe("127.0.0.1");
		const error = await fetch(`${origin}/anything`).then(
			() => undefined,
			(thrown: unknown) => thrown,
		);
		expect(error).toMatchObject({ name: "TypeError", cause: { code: "ECONNREFUSED" } });
	});

	it("is one fixed origin, on a port below every ephemeral range", async () => {
		const origin = await refusedOrigin();
		expect(await refusedOrigin()).toBe(origin);
		expect(Number(new URL(origin).port)).toBeLessThan(1024);
	});
});

describe("assertConnectionRefused — the probe refusedOrigin runs", () => {
	it("rejects, naming the origin, when something answers there", async () => {
		const server = createServer((socket) => socket.destroy());
		servers.push(server);
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const { port } = server.address() as { port: number };
		const origin = `http://127.0.0.1:${port}`;
		await expect(assertConnectionRefused(origin)).rejects.toThrow(
			`${origin} does not refuse connections`,
		);
	});
});
