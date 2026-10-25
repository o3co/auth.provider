import { createServer } from "node:http";
import { type AddressInfo, connect, type Socket } from "node:net";

/** The tunnel as it runs: its port on loopback, and the destinations it opened, in order. */
export interface Tunnel {
	readonly port: number;
	opened(): readonly string[];
	stop(): Promise<void>;
}

/**
 * A CONNECT proxy on loopback for the app's outbound: it opens a tunnel only to a destination
 * `allow` names (`host:port`, as the app names it), to where that destination listens; any other,
 * and any other method, is refused. The app's own TLS runs inside the tunnel, its checks unchanged.
 */
export async function startTunnel(given: {
	readonly allow: Readonly<Record<string, string>>;
}): Promise<Tunnel> {
	const opened: string[] = [];
	const sockets = new Set<Socket>();
	const server = createServer((_req, res) => {
		res.writeHead(405, { allow: "CONNECT" });
		res.end();
	});
	server.on("connect", (req, client: Socket, head: Buffer) => {
		sockets.add(client);
		client.on("close", () => sockets.delete(client));
		client.on("error", () => client.destroy());
		const target = req.url ?? "";
		const at = given.allow[target];
		if (at === undefined) {
			client.end("HTTP/1.1 403 Forbidden\r\n\r\n");
			return;
		}
		const [host, port] = [
			at.slice(0, at.lastIndexOf(":")),
			Number(at.slice(at.lastIndexOf(":") + 1)),
		];
		const upstream = connect(port, host, () => {
			opened.push(target);
			client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
			if (head.length > 0) upstream.write(head);
			upstream.pipe(client);
			client.pipe(upstream);
		});
		sockets.add(upstream);
		upstream.on("close", () => {
			sockets.delete(upstream);
			client.destroy();
		});
		upstream.on("error", () => {
			if (!client.destroyed && opened.at(-1) !== target)
				client.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
			else client.destroy();
		});
	});
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => resolve());
	});
	return {
		port: (server.address() as AddressInfo).port,
		opened: () => [...opened],
		stop: () =>
			new Promise<void>((resolve) => {
				for (const socket of sockets) socket.destroy();
				server.close(() => resolve());
			}),
	};
}
