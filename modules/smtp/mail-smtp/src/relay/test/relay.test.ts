import { connect, createServer, Socket } from "node:net";
import { expect, it } from "vitest";
import { isLoopback, isLoopbackHost, mailboxOf, RelayFailure, relayOver } from "../relay.ts";

it("reads loopback addresses, IPv4-mapped ones included, and nothing else", () => {
	for (const address of ["127.0.0.1", "127.9.8.7", "::1", "::ffff:127.0.0.1"]) {
		expect(isLoopback(address), address).toBe(true);
	}
	for (const address of [undefined, "", "10.0.0.1", "::ffff:10.0.0.1", "::2", "localhost"]) {
		expect(isLoopback(address), String(address)).toBe(false);
	}
	expect(isLoopbackHost("LocalHost")).toBe(true);
	for (const host of ["127.0.0.08", "2130706433", "localhost.example"]) {
		expect(isLoopbackHost(host), host).toBe(false);
	}
});

it("reads one mailbox from `from`, with or without a display name, leaving its address to the section", () => {
	expect(mailboxOf("Provider <noreply@example.test>")).toEqual({
		name: "Provider",
		address: "noreply@example.test",
	});
	expect(mailboxOf("noreply@example.test")).toEqual({ name: "", address: "noreply@example.test" });
	expect(mailboxOf("Provider <a%b@example.test>")?.address).toBe("a%b@example.test");
	for (const from of ["a@example.test, b@example.test", "Group: a@example.test;", ""]) {
		expect(mailboxOf(from), from).toBeUndefined();
	}
});

it("under none, sends nothing when the connected peer is not loopback", async () => {
	let received = 0;
	const server = createServer((socket) => {
		socket.on("error", () => {});
		socket.on("data", (chunk) => {
			received += chunk.length;
		});
		socket.write("220 relay.test ESMTP\r\n");
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as { port: number };
	// The peer as a name that resolved elsewhere would show it.
	const elsewhere = (host: string, at: number) => {
		const socket = connect({ host, port: at });
		Object.defineProperty(socket, "remoteAddress", { get: () => "192.0.2.1" });
		return socket;
	};
	const deliver = relayOver(
		{
			host: "localhost",
			port,
			security: "none",
			from: { name: "", address: "noreply@example.test" },
			deadlineMs: 1000,
		},
		elsewhere,
	);
	const failure = await deliver({ to: "a@example.test", subject: "s", text: "t" }).catch(
		(e: unknown) => e,
	);
	expect(failure).toBeInstanceOf(RelayFailure);
	expect((failure as RelayFailure).stage).toBe("security");
	await new Promise((resolve) => setTimeout(resolve, 50));
	expect(received).toBe(0);
	await new Promise((resolve) => server.close(resolve));
});

it("gives up on a connection that never opens at the connecting deadline, a quarter of the whole", async () => {
	// A socket that never connects or fails, as a peer dropping every packet would leave it.
	const silent = () => new Socket();
	const deliver = relayOver(
		{
			host: "relay.test",
			port: 25,
			security: "starttls",
			from: { name: "", address: "noreply@example.test" },
			deadlineMs: 400,
		},
		silent,
	);
	const failure = await deliver({ to: "a@example.test", subject: "s", text: "t" }).catch(
		(e: unknown) => e,
	);
	expect(failure).toMatchObject({ stage: "connection", codes: { code: "ETIMEDOUT" } });
});
