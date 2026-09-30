/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The SMTP mail sender's section, `smtp-mail-sender` (the MFA ADR's D5, D19,
 * D20): the relay's host and port, how the connection is secured, the
 * account it signs in with, and the sender's address. Strict: a key the
 * section does not know is refused. Every leaf reads the string an
 * environment variable carries. `secure` is `starttls` (upgrade a plain
 * connection, port 587 by default), `tls` (implicit TLS) or `none`, which is
 * refused to a host that is not loopback: a code or a notice never crosses a
 * network in the clear. The host, account and address have no default.
 */

import { isLoopbackHostname } from "@o3co/auth-provider-core";
import { z } from "zod";

/** The ways a connection to the relay is secured. */
export const SMTP_SECURE_MODES = ["starttls", "tls", "none"] as const;

const SECTION_MISSING =
	"is missing: layer @o3co/auth-provider-smtp/reference.conf beneath the composition's configuration";

/** A section's refusal: missing, or written as a value rather than a section of keys. */
const sectionError = (issue: { readonly input?: unknown }): string =>
	issue.input === undefined ? SECTION_MISSING : "must be a section of keys";

const PORT_RULE = "must be a whole number from 1 to 65535";
const port = z.union(
	[
		z
			.number({ error: PORT_RULE })
			.int({ error: PORT_RULE })
			.min(1, { error: PORT_RULE })
			.max(65_535, {
				error: PORT_RULE,
			}),
		z
			.string({ error: PORT_RULE })
			.trim()
			.regex(/^\d+$/, { error: PORT_RULE })
			.transform(Number)
			.pipe(z.number().int().min(1, { error: PORT_RULE }).max(65_535, { error: PORT_RULE })),
	],
	{ error: PORT_RULE },
);

/** Whether `text` carries a C0 control character, DEL or a C1 control character. */
function hasControlCharacter(text: string): boolean {
	for (let index = 0; index < text.length; index++) {
		const code = text.charCodeAt(index);
		if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
	}
	return false;
}

const TEXT_RULE = "must be well-formed text on one line, not blank, with no control character";

/** One line of text a relay's greeting, an account or a header carries. */
const lineOfText = z
	.string({ error: TEXT_RULE })
	.refine((text) => text.isWellFormed() && text.trim() !== "" && !hasControlCharacter(text), {
		error: TEXT_RULE,
	});

/** The SMTP mail sender's section, as its module parses it before any factory runs. */
export const smtpMailSenderConfigSchema = z
	.strictObject(
		{
			host: lineOfText.optional(),
			port,
			secure: z.enum(SMTP_SECURE_MODES, { error: 'must be "starttls", "tls" or "none"' }),
			user: lineOfText.optional(),
			password: z.string({ error: "must be a string" }).optional(),
			from: lineOfText.optional(),
		},
		{ error: sectionError },
	)
	.superRefine((section, context) => {
		if (
			section.secure === "none" &&
			section.host !== undefined &&
			!isLoopbackHostname(section.host)
		) {
			context.addIssue({
				code: "custom",
				path: ["secure"],
				message:
					'is "none" to a host that is not loopback: use "starttls" or "tls", or relay through a loopback host',
			});
		}
	});

/** `smtp-mail-sender` as its schema reads it. */
export type SmtpMailSenderSettings = z.infer<typeof smtpMailSenderConfigSchema>;
