import { createServer, type Server, type Socket } from "node:net";

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

/**
 * Just enough of a Redis 7 primary to boot the module, counting PINGs per socket. Its role and
 * settings may change; a command named in `refused` is refused for want of permission. The check's
 * script answers as the real one reports: each command in `scripts.refused` refused in the words of
 * `scripts.wording`'s Redis, each in `scripts.keysRefusedIn` refused its key in those words, and
 * each write NOREPLICAS while `writes.noReplicas`; with
 * `scripts.keysRefused`, the script is refused its keys before it runs.
 */
export function fakeRedis() {
	const sockets = new Set<Socket>();
	const pinged = new Set<Socket>();
	const settings: Record<string, string> = { role: "master", "maxmemory-policy": "noeviction" };
	const refused = new Set<string>();
	const scripts = {
		refused: [] as string[],
		wording: "7.4" as "7.0" | "7.4",
		keysRefused: false,
		keysRefusedIn: [] as string[],
	};
	const writes = { noReplicas: false };
	const writing = new Set(["SET", "INCR", "HSET", "HINCRBY", "PEXPIRE", "PEXPIREAT", "DEL"]);
	const refusal = (name: string) =>
		scripts.wording === "7.0"
			? "ERR The user executing the script can't run this command or subcommand"
			: `ERR ACL failure in script: User u has no permissions to run the '${name.toLowerCase()}' command`;
	const keyRefusal = () =>
		scripts.wording === "7.0"
			? "ERR The user executing the script can't access at least one of the keys mentioned in the command arguments"
			: "ERR ACL failure in script: No permissions to access a key";
	/** The check script's report: each command that failed, then its error. */
	const report = () => {
		const failed = [
			...scripts.refused.map((name) => [name, refusal(name)]),
			...scripts.keysRefusedIn.map((name) => [name, keyRefusal()]),
			...(writes.noReplicas
				? [...writing].map((name) => [name, "NOREPLICAS Not enough good replicas to write."])
				: []),
		].flat();
		return `*${failed.length}\r\n${failed.map(bulk).join("")}`;
	};
	const reply = (args: readonly string[]): string => {
		const name = args[0]?.toUpperCase() ?? "";
		if (refused.has(name)) {
			return `-NOPERM User default has no permissions to run the '${name.toLowerCase()}' command\r\n`;
		}
		if (name === "EVAL" && scripts.keysRefused) return "-NOPERM No permissions to access a key\r\n";
		if (name === "EVAL") return report();
		if (name === "SET" && writes.noReplicas)
			return "-NOREPLICAS Not enough good replicas to write.\r\n";
		if (name === "PING") return "+PONG\r\n";
		if (name === "INFO")
			return bulk("redis_version:7.4.0\r\ncluster_enabled:0\r\nloading:0\r\nrun_id:abc\r\n");
		if (name === "ROLE") return `*3\r\n${bulk(settings.role ?? "")}:0\r\n*0\r\n`;
		const setting = args[2] ?? "";
		if (name === "CONFIG" && settings[setting] !== undefined) {
			return `*2\r\n${bulk(setting)}${bulk(settings[setting] ?? "")}`;
		}
		return "+OK\r\n";
	};
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
				socket.write(reply(command.args));
			}
		});
	});
	return {
		pinged,
		settings,
		refused,
		scripts,
		writes,
		listen: () =>
			new Promise<number>((resolve) =>
				server.listen(0, "127.0.0.1", () => {
					const address = server.address();
					resolve(typeof address === "object" && address ? address.port : 0);
				}),
			),
		/**
		 * Bytes no reply starts with, so the client's parser refuses them and reports an error event
		 * whatever command is waiting; a stray `+PONG` could be taken as one in flight's reply.
		 */
		stray: () => {
			for (const socket of sockets) socket.write("@\r\n");
		},
		down: () => {
			server.close();
			for (const socket of sockets) socket.destroy();
		},
	};
}
