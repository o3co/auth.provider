import { connect } from "node:net";
import { afterEach, expect, it } from "vitest";
import { type FakeSmtp, fakeSmtp } from "../src/testing.ts";

let running: FakeSmtp | undefined;
afterEach(async () => {
	await running?.stop();
	running = undefined;
});

/** Speaks SMTP as a sender does: a reply after each command, and in a message's data only after its last line. */
async function send(fake: FakeSmtp, lines: readonly string[]) {
	const socket = connect(fake.port, fake.host);
	socket.on("error", () => undefined);
	let buffered = "";
	socket.on("data", (chunk: Buffer) => {
		buffered += chunk.toString();
	});
	/** The next complete reply: its last line starts with a code and a space. */
	const reply = async () => {
		for (;;) {
			const match = /^(\d{3}) [^\r]*\r\n/m.exec(buffered);
			if (match) {
				buffered = buffered.slice(match.index + match[0].length);
				return match[1] as string;
			}
			await new Promise((r) => setTimeout(r, 5));
		}
	};
	const codes = [await reply()];
	let inData = false;
	for (const line of lines) {
		socket.write(`${line}\r\n`);
		if (inData && line !== ".") continue;
		codes.push(await reply());
		inData = line === "DATA";
	}
	socket.end();
	return codes;
}

it("takes a message as a sender sends it, and answers the latest to an address", async () => {
	// A free port, so runs at once never meet.
	running = await fakeSmtp();
	const replies = await send(running, [
		"EHLO sender",
		"MAIL FROM:<from@issuer.example>",
		"RCPT TO:<Ann@Example.com>",
		"DATA",
		"Subject: Your code",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		"Your code is 123=",
		"456.",
		"..dot",
		".",
		"QUIT",
	]);
	expect(replies.map((r) => r.slice(0, 3))).toEqual([
		"220",
		"250",
		"250",
		"250",
		"354",
		"250",
		"221",
	]);
	expect(running.latestTo("ann@example.com")).toMatchObject({
		from: "from@issuer.example",
		to: ["Ann@Example.com"],
		headers: { subject: "Your code" },
		text: "Your code is 123456.\r\n.dot",
	});
	expect(running.latestTo("bob@example.com")).toBeUndefined();
});

it("refuses to start where its address is taken, rather than take another", async () => {
	running = await fakeSmtp();
	await expect(fakeSmtp(running.port)).rejects.toThrow(/127\.0\.0\.1:\d+ is in use/);
});
