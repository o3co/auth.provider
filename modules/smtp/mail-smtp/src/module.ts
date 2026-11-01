import { defineModule, Unavailable } from "@mod/kernel";
import { canonicalAddress, type Message, mail, preparer, preparerTakes } from "@mod/mail";
import { isFloor, tlsOptions } from "@mod/tls-options";
import { RelayFailure, relayOver, type Stage } from "./relay/relay.ts";
import { section } from "./section.ts";

/** What a failure log line may hold: the stage and the codes, never the relay's words. Its keys are
 * spelled out, so the log's type checks them as it checks a line's own names. */
type Logged = { readonly stage: Stage | "unknown" } & {
	readonly [K in keyof RelayFailure["codes"]]: RelayFailure["codes"][K];
};

function logged(failure: unknown): Logged {
	if (!(failure instanceof RelayFailure)) return { stage: "unknown" };
	return { stage: failure.stage, ...failure.codes };
}

/** The SMTP sender: each send is one connection to the operator's relay. It takes what mail's preparer takes, and tls-options' floor. */
export default defineModule(
	{ name: "mail-smtp", section, replicaSafe: true, takes: [...preparerTakes, tlsOptions] },
	(m) => [
		m.provide(mail).by(async (c) => {
			const prepare = await preparer(c);
			const floor = await c.get(tlsOptions);
			if (!isFloor(floor)) {
				c.refuse(
					"mail-smtp",
					"the TLS floor is not one tls-options made: provide it from @mod/tls-options",
				);
			}
			const { host, port, security, from, user, password } = c.section;
			if (security === "none") c.log.warn("mail-smtp.plaintext");
			const deliver = relayOver({
				host,
				port,
				security,
				from,
				account:
					user !== undefined && password !== undefined ? { user, pass: password } : undefined,
				deadlineMs: c.section.deadline,
				floor,
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
	],
);
