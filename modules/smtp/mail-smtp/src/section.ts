import { canonicalAddress, isAddress } from "@mod/mail";
import { z } from "zod";
import { isLoopbackHost, mailboxOf } from "./relay/relay.ts";

/** One line of text: well formed, not blank, no control character. */
const line = z.string().refine((s) => s.isWellFormed() && s.trim() !== "" && !/\p{Cc}/u.test(s), {
	error: "must be one line of text, not blank, with no control character",
});

export const section = z
	.strictObject({
		host: line,
		port: z.number().int().min(1).max(65_535).default(587),
		security: z.enum(["starttls", "tls", "none"]).default("starttls"),
		from: line.transform((from, ctx) => {
			const mailbox = mailboxOf(from);
			// Kept in mail's canonical form: a domain beyond ASCII goes out in IDNA's ASCII form.
			const address = mailbox && isAddress(mailbox.address) && canonicalAddress(mailbox.address);
			if (mailbox && address) return Object.freeze({ name: mailbox.name, address });
			ctx.addIssue({
				code: "custom",
				message: "must name one mailbox, alone or after a display name",
			});
			return z.NEVER;
		}),
		user: line.optional(),
		password: line.optional(),
		"deadline-ms": z.number().int().min(100).max(600_000).default(40_000),
		"concurrent-sends": z.number().int().min(1).max(1000).default(20),
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
