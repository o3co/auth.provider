import { setting } from "@mod/kernel";
import { canonicalAddress, isAddress } from "@mod/mail";
import { z } from "zod";
import { isLoopbackHost, mailboxOf } from "./relay/relay.ts";

/** One line of text: well formed, not blank, no control character. */
const line = z.string().refine((s) => s.isWellFormed() && s.trim() !== "" && !/\p{Cc}/u.test(s), {
	error: "must be one line of text, not blank, with no control character",
});

export const section = z
	.strictObject({
		host: line.describe("The relay's host name or address."),
		port: z
			.number()
			.int()
			.min(1)
			.max(65_535)
			.prefault(587)
			.describe("The relay's port, from 1 to 65535."),
		security: z
			.enum(["starttls", "tls", "none"])
			.prefault("starttls")
			.describe(
				"How the connection is secured: STARTTLS after connecting, TLS from the first byte, or none, only to a loopback host.",
			),
		from: line
			.transform((from, ctx) => {
				const mailbox = mailboxOf(from);
				// Kept in mail's canonical form: a domain beyond ASCII goes out in IDNA's ASCII form.
				const address = mailbox && isAddress(mailbox.address) && canonicalAddress(mailbox.address);
				if (mailbox && address) return Object.freeze({ name: mailbox.name, address });
				ctx.addIssue({
					code: "custom",
					message: "must name one mailbox, alone or after a display name",
				});
				return z.NEVER;
			})
			.describe("The sender: one mailbox, alone or after a display name."),
		user: line.optional().describe("The account the relay signs in, beside `password`."),
		password: line.optional().describe("The account's password, beside `user`."),
		deadline: setting
			.duration("ms")
			.pipe(z.number().int().min(100).max(600_000))
			.prefault("40s")
			.describe("How long a whole send may take, from 100ms to 10m."),
		"concurrent-sends": z
			.number()
			.int()
			.min(1)
			.max(1000)
			.prefault(20)
			.describe("Sends under way at once on a host, from 1 to 1000."),
	})
	.superRefine((s, ctx) => {
		if (s.user !== undefined && s.password === undefined) {
			ctx.addIssue({ code: "custom", path: ["password"], message: "is needed with user" });
		}
		if (s.password !== undefined && s.user === undefined) {
			ctx.addIssue({ code: "custom", path: ["user"], message: "is needed with password" });
		}
		if (s.security === "none" && !isLoopbackHost(s.host)) {
			ctx.addIssue({
				code: "custom",
				path: ["security"],
				message: "none needs host localhost or a loopback address; use starttls or tls",
			});
		}
	});
