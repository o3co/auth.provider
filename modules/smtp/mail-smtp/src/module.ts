import { defineModule, type LogFields, Unavailable } from "@mod/kernel";
import { canonicalAddress, type Message, mail, preparer } from "@mod/mail";
import { RelayFailure, relayOver } from "./relay/relay.ts";
import { section } from "./section.ts";

/** What a failure log line may hold: the stage and the codes, never the relay's words. */
function logged(failure: unknown): LogFields {
	if (!(failure instanceof RelayFailure)) return { stage: "unknown" };
	return { stage: failure.stage, ...failure.codes };
}

/** The SMTP sender: each send is one connection to the operator's relay. */
export default defineModule({ name: "mail-smtp", section, replicaSafe: true }, (m) => [
	m.provide(mail).by(async (c) => {
		const prepare = await preparer(c);
		const { host, port, security, from, user, password } = c.section;
		if (security === "none") c.log.warn("mail-smtp.plaintext");
		const deliver = relayOver({
			host,
			port,
			security,
			from,
			account: user !== undefined && password !== undefined ? { user, pass: password } : undefined,
			deadlineMs: c.section["deadline-ms"],
		});
		const most = c.section["concurrent-sends"];
		// Sends on this host now; each holds a connection until its answer or its deadline.
		let running = 0;
		return Object.freeze({
			send: async (input: Message) => {
				const { message, subject, text } = prepare(input);
				// Refused before connecting: a send past the limit opens nothing.
				if (running >= most) {
					c.log.warn("mail-smtp.busy", { purpose: message.purpose });
					throw new Unavailable("mail");
				}
				// mail's preparer has taken the address, so its canonical form exists: the domain in ASCII.
				const to = canonicalAddress(message.to);
				if (to === undefined) throw new TypeError("mail-smtp: an address the preparer took");
				running += 1;
				const answer = await deliver({ to, subject, text })
					.catch((failure: unknown) => {
						c.log.warn("mail-smtp.unsent", { purpose: message.purpose, ...logged(failure) });
						throw new Unavailable("mail");
					})
					.finally(() => {
						running -= 1;
					});
				if (answer === "limited") c.log.info("mail-smtp.limited", { purpose: message.purpose });
				return answer;
			},
		});
	}),
]);
