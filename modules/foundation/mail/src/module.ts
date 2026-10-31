import { createHmac } from "node:crypto";
import { defineModule } from "@mod/kernel";
import { type Message, mail, preparerTakes } from "./contract.ts";
import { preparer } from "./prepare.ts";
import { section } from "./section.ts";

/** The logging-only sender: it sends nothing and logs no address and no value. */
export default defineModule(
	{ name: "mail", section, replicaSafe: false, takes: preparerTakes },
	(m) => [
		m.provide(mail).by(async (c) => {
			if (!c.section["accept-unsent"]) {
				return c.refuse("mail.accept-unsent", "this sender sends nothing; set true to accept that");
			}
			// Accepted, yet said at every start: no code or link mailed reaches its user.
			c.log.warn("mail.unsent_accepted", { reason: "the logging-only sender sends nothing" });
			const prepare = await preparer(c);
			// A key per process: the hash links lines of one run, yet a known address cannot be looked up.
			const key = c.random.bytes(32);
			return Object.freeze({
				send: async (input: Message) => {
					const { message } = prepare(input);
					c.log.info("mail.not_sent", {
						purpose: message.purpose,
						to: createHmac("sha256", key).update(message.to).digest("hex").slice(0, 16),
						values: Object.keys(message.values).sort().join(","),
					});
					return "sent" as const;
				},
			});
		}),
	],
);
