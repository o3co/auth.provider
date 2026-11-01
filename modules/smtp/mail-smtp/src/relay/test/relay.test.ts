import { connect, createServer, Socket } from "node:net";
import { testTlsOptions } from "@mod/tls-options/testing";
import { expect, it } from "vitest";
import { answerOf } from "../answers.ts";
import { mailboxOf, RelayFailure, relayOver } from "../relay.ts";

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
			floor: testTlsOptions,
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
			floor: testTlsOptions,
		},
		silent,
	);
	const failure = await deliver({ to: "a@example.test", subject: "s", text: "t" }).catch(
		(e: unknown) => e,
	);
	expect(failure).toMatchObject({ stage: "connection", codes: { code: "ETIMEDOUT" } });
});

it("keeps a TLS alert's number only of a TLS failure carrying no reply, and only one an alert can have", () => {
	const phase = { securing: true, awaitingGreeting: false };
	const failed = (failure: object) => (answerOf(failure, phase) as RelayFailure).codes.alert;
	const refused =
		"error:0A000410:SSL routines::ssl/tls alert handshake failure:SSL alert number 40";
	expect(failed({ code: "ETLS", message: refused })).toBe(40);
	expect(failed({ code: "ESOCKET", message: `${refused}\n` })).toBe(40);
	expect(failed({ code: "ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE", message: refused })).toBe(40);
	// The library adds a reply's words to the message: a relay cannot write an alert there.
	const reply = "554 5.7.1 SSL alert number 7";
	expect(failed({ code: "ETLS", message: `Error: ${reply}`, response: reply })).toBeUndefined();
	expect(failed({ code: "EPROTOCOL", message: refused })).toBeUndefined();
	expect(failed({ code: "ETLS", message: "SSL alert number 999" })).toBeUndefined();
});
