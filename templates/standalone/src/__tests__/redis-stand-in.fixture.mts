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
 * A TCP stand-in for a Redis server, for the tests that boot the template
 * against a socket and need no real server: it records what each connection
 * sends and answers as a server that runs `noeviction` does.
 */

import { once } from "node:events";
import { type AddressInfo, createServer, type Socket } from "node:net";

/** The first command `buffer` holds in full, as RESP sends it, and its length; `undefined` until it does. */
function nextCommand(
	buffer: string,
): { readonly name: string; readonly length: number } | undefined {
	const header = /^\*(\d+)\r\n/.exec(buffer);
	if (header === null) return undefined;
	let at = header[0].length;
	const args: string[] = [];
	for (let i = 0; i < Number(header[1]); i++) {
		const bulk = /^\$(\d+)\r\n/.exec(buffer.slice(at));
		if (bulk === null) return undefined;
		const start = at + bulk[0].length;
		const end = start + Number(bulk[1]);
		if (buffer.length < end + 2) return undefined;
		args.push(buffer.slice(start, end));
		at = end + 2;
	}
	return { name: (args[0] ?? "").toLowerCase(), length: at };
}

/** What a server that runs `noeviction` and speaks RESP2 answers `name`. */
function replyTo(name: string): string {
	if (name === "hello") return "-NOPROTO unsupported protocol version\r\n";
	if (name === "info") {
		const info =
			"# Memory\r\nmaxmemory_policy:noeviction\r\n# Persistence\r\naof_enabled:1\r\nloading:0\r\n";
		return `$${Buffer.byteLength(info)}\r\n${info}\r\n`;
	}
	return "+OK\r\n";
}

/**
 * A TCP server standing in for Redis: it records what each connection sends,
 * and answers as a server running `noeviction` does — `HELLO` refused, so the
 * client speaks RESP2, `INFO` with the policy, anything else `OK` — so a
 * client dialled at it writes its handshake and the stores whose factories
 * read the policy build.
 */
export async function listeningRedis(): Promise<{
	readonly port: number;
	readonly received: () => string;
	readonly close: () => Promise<void>;
}> {
	const sockets = new Set<Socket>();
	let received = "";
	const server = createServer((socket) => {
		sockets.add(socket);
		let pending = "";
		socket.on("close", () => sockets.delete(socket));
		socket.on("data", (chunk) => {
			received += chunk.toString("utf8");
			pending += chunk.toString("utf8");
			for (let command = nextCommand(pending); command; command = nextCommand(pending)) {
				pending = pending.slice(command.length);
				socket.write(replyTo(command.name));
			}
		});
	});
	server.listen(0, "127.0.0.1");
	await once(server, "listening");
	const { port } = server.address() as AddressInfo;
	return {
		port,
		received: () => received,
		close: async () => {
			for (const socket of sockets) socket.destroy();
			await new Promise<void>((resolve) => server.close(() => resolve()));
		},
	};
}
