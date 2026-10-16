import { createServer, type Server, type Socket } from "node:net";
import {
	type Assembly,
	assemble,
	type BuildContext,
	contract,
	defineModule,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { afterEach, describe, expect, it } from "vitest";
import redisModule from "../src/module.ts";

/** One command from the start of `buffer`, and the bytes it took; none until it is whole. */
function commandOf(buffer: Buffer): { args: string[]; used: number } | undefined {
	const text = buffer.toString("latin1");
	let at = 0;
	const line = () => {
		const end = text.indexOf("\r\n", at);
		if (end < 0) return undefined;
		const read = text.slice(at, end);
		at = end + 2;
		return read;
	};
	const head = line();
	if (head === undefined) return undefined;
	const args: string[] = [];
	for (let i = 0; i < Number(head.slice(1)); i++) {
		const size = Number(line()?.slice(1));
		if (Number.isNaN(size) || text.length < at + size + 2) return undefined;
		args.push(text.slice(at, at + size));
		at += size + 2;
	}
	return { args, used: at };
}

const bulk = (text: string) => `$${text.length}\r\n${text}\r\n`;

/** Just enough of a Redis 7 primary to boot the module with no spaces, counting PINGs per socket. */
function fakeRedis() {
	const sockets = new Set<Socket>();
	const pinged = new Set<Socket>();
	const server: Server = createServer((socket) => {
		sockets.add(socket);
		socket.on("close", () => sockets.delete(socket));
		socket.on("error", () => {});
		let buffer = Buffer.alloc(0);
		socket.on("data", (chunk: Buffer) => {
			buffer = Buffer.concat([buffer, chunk]);
			for (let command = commandOf(buffer); command; command = commandOf(buffer)) {
				buffer = buffer.subarray(command.used);
				const name = command.args[0]?.toUpperCase();
				if (name === "PING") pinged.add(socket);
				socket.write(
					name === "PING"
						? "+PONG\r\n"
						: name === "INFO"
							? bulk("redis_version:7.4.0\r\ncluster_enabled:0\r\nloading:0\r\n")
							: name === "ROLE"
								? `*3\r\n${bulk("master")}:0\r\n*0\r\n`
								: "+OK\r\n",
				);
			}
		});
	});
	return {
		pinged,
		listen: () =>
			new Promise<number>((resolve) =>
				server.listen(0, "127.0.0.1", () => {
					const address = server.address();
					resolve(typeof address === "object" && address ? address.port : 0);
				}),
			),
		/** A reply no command asked for: the client reports it as an error event. */
		stray: () => {
			for (const socket of sockets) socket.write("+PONG\r\n");
		},
		down: () => {
			server.close();
			for (const socket of sockets) socket.destroy();
		},
	};
}

let app: Assembly | undefined;
afterEach(async () => {
	await app?.stop(1000);
	app = undefined;
});

async function boot(port: number) {
	const recorded = recordingLog();
	let context: BuildContext<unknown> | undefined;
	const asker = defineModule({ name: "asker" }, (m) => [
		m.provide(contract<object>("asker")).by((c) => {
			context = c;
			return {};
		}),
	]);
	app = await assemble({
		modules: [redisModule, asker],
		config: { ...kernelConfig(), redis: { url: `redis://127.0.0.1:${port}` } },
		runtime: quietRuntime({
			clock: { now: () => 0 },
			random: { bytes: (n) => new Uint8Array(n) },
			log: recorded.log,
		}),
	});
	/** The events of the warn lines so far. */
	const warned = () =>
		recorded
			.lines()
			.filter((line) => line.level === "warn")
			.map((line) => line.event);
	return { warned, ready: () => context?.readinessReport(1000).then((r) => r.answer) };
}

describe("the redis probe", () => {
	it("passes when both connections answer PING", async () => {
		const redis = fakeRedis();
		const { ready } = await boot(await redis.listen());
		redis.pinged.clear();
		expect(await ready()).toBe("ready");
		expect(redis.pinged.size).toBe(2);
		redis.down();
	});

	it("fails once the server is gone", async () => {
		const redis = fakeRedis();
		const { ready } = await boot(await redis.listen());
		redis.down();
		await new Promise((resolve) => setTimeout(resolve, 20));
		expect(await ready()).toBe("unready");
	});

	it("logs an error event instead of letting it end the process, and then answers unready", async () => {
		const redis = fakeRedis();
		const { warned, ready } = await boot(await redis.listen());
		redis.stray();
		await new Promise((resolve) => setTimeout(resolve, 20));
		expect(warned()).toContain("redis.error");
		redis.down();
		await new Promise((resolve) => setTimeout(resolve, 20));
		expect(await ready()).toBe("unready");
	});
});
