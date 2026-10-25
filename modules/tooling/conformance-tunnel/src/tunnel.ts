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
	// Own entries alone: a name like `constructor` is no destination.
	const allowed = new Map(Object.entries(given.allow));
	const server = createServer((_req, res) => {
		res.writeHead(405, { allow: "CONNECT" });
		res.end();
	});
	server.on("connect", (req, client: Socket, head: Buffer) => {
		sockets.add(client);
		client.on("error", () => client.destroy());
		const target = req.url ?? "";
		const at = allowed.get(target);
		if (at === undefined) {
			client.on("close", () => sockets.delete(client));
			client.end("HTTP/1.1 403 Forbidden\r\n\r\n");
			return;
		}
		const colon = at.lastIndexOf(":");
		/** Whether this request's own tunnel opened: an error before is a 502, after it ends the tunnel. */
		let established = false;
		const upstream = connect(Number(at.slice(colon + 1)), at.slice(0, colon), () => {
			established = true;
			opened.push(target);
			client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
			if (head.length > 0) upstream.write(head);
			upstream.pipe(client);
			client.pipe(upstream);
		});
		sockets.add(upstream);
		// A client gone, however abruptly, takes its tunnel's other side with it, opened or opening.
		client.on("close", () => {
			sockets.delete(client);
			upstream.destroy();
		});
		upstream.on("close", () => {
			sockets.delete(upstream);
			client.destroy();
		});
		upstream.on("error", () => {
			if (!established && !client.destroyed) client.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
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
