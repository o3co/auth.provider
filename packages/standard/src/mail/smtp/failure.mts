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
 * What a failed SMTP exchange comes to, and the error the SMTP sender
 * rejects with. The one place the transport's vocabulary — its error codes,
 * the command it was at, the relay's reply — is read.
 *
 * A limit is a transient reply (`421`, `450`, `451`, `452`) to the sender,
 * the recipient or the message whose enhanced status code (RFC 3463) is
 * `4.7.1`, `4.7.28` (mail flood) or `4.5.3` (too many recipients). Anything
 * else, a reply without an enhanced code included, is an outage.
 *
 * A `MailTransportError` is built from a closed reason, the stage, and the
 * reply's codes alone: never the reply's text or the transport's, which can
 * quote the recipient, the code or the credentials, and never a `cause`.
 */

/** Why a send failed, as an operator acts on it. */
export type MailTransportFailure =
	/**
	 * No connection the sender may deliver over: the name did not resolve;
	 * the connection was refused, reset or closed, or the relay turned it
	 * away; or it could not be secured as `secure` requires — STARTTLS
	 * refused, the TLS handshake or the relay's certificate refused, or,
	 * under `none`, the connected address not loopback.
	 */
	| "unreachable"
	/** The relay refused the account's credentials. */
	| "auth_failed"
	/** The relay refused the sender, the recipient or the message, or put it off with a reply that is not a limit. */
	| "rejected"
	/** No connection, greeting or answer within its time. */
	| "timeout";

/** A relay's reply as the error keeps it: its codes, never its text. */
interface ReplyCodes {
	readonly code: number;
	readonly enhanced: string | undefined;
}

/**
 * A send the SMTP sender could not make. `name`, `reason`, `replyCode` and
 * `enhancedCode` are part of the contract; the message names the stage and
 * the reply's codes, and nothing the relay or the transport wrote.
 */
export class MailTransportError extends Error {
	readonly reason: MailTransportFailure;
	/** The relay's reply code (RFC 5321 §4.2), when the failure was a reply. */
	readonly replyCode: number | undefined;
	/** The reply's enhanced status code (RFC 3463), when it carried one. */
	readonly enhancedCode: string | undefined;

	constructor(what: string, reason: MailTransportFailure, reply?: ReplyCodes) {
		const codes =
			reply === undefined
				? ""
				: ` (SMTP ${reply.code}${reply.enhanced === undefined ? "" : ` ${reply.enhanced}`})`;
		super(`standard-smtp-mail-sender: ${what}${codes}`);
		this.name = "MailTransportError";
		this.reason = reason;
		this.replyCode = reply?.code;
		this.enhancedCode = reply?.enhanced;
	}
}

/** A reply's first line: its code, and the enhanced code of the same class after it. */
const REPLY = /^([2-5])\d\d(?:[ -]([2-5])\.(\d{1,3})\.(\d{1,3})(?=[ \r\n]|$))?/;

/** The codes of `response`, a reply as the transport kept it, or none. */
function replyCodesOf(response: unknown): ReplyCodes | undefined {
	if (typeof response !== "string") return undefined;
	const match = REPLY.exec(response);
	if (match === null) return undefined;
	const [whole, replyClass, enhancedClass, subject, detail] = match;
	const code = Number(whole.slice(0, 3));
	const enhanced =
		enhancedClass === replyClass && enhancedClass !== undefined
			? `${enhancedClass}.${Number(subject)}.${Number(detail)}`
			: undefined;
	return { code, enhanced };
}

/** The transport's commands a refusal of this mail answers, as the stage the error names. */
const MAIL_STAGES: Readonly<Record<string, string>> = {
	"MAIL FROM": "the sender",
	"RCPT TO": "the recipient",
	DATA: "the message",
};

const LIMIT_REPLIES: ReadonlySet<number> = new Set([421, 450, 451, 452]);
const LIMIT_ENHANCED_CODES: ReadonlySet<string> = new Set(["4.7.1", "4.7.28", "4.5.3"]);

/** A string property of `value`, or none. */
const stringOf = (value: unknown, key: string): string | undefined => {
	if (typeof value !== "object" || value === null) return undefined;
	const property: unknown = (value as Record<string, unknown>)[key];
	return typeof property === "string" ? property : undefined;
};

/**
 * `failure`, what the SMTP exchange failed with, as the sender answers it:
 * `refused_at_limit`, or the `MailTransportError` it rejects with.
 */
export function readSendFailure(failure: unknown): "refused_at_limit" | MailTransportError {
	const code = stringOf(failure, "code");
	const stage = MAIL_STAGES[stringOf(failure, "command") ?? ""];
	const reply = replyCodesOf(stringOf(failure, "response"));
	if (code === "ETIMEDOUT")
		return new MailTransportError("the relay did not answer in time", "timeout");
	if (code === "EAUTH") {
		return new MailTransportError(
			"the relay refused the account's credentials",
			"auth_failed",
			reply,
		);
	}
	if (stage !== undefined && reply !== undefined && (code === "EENVELOPE" || code === "EMESSAGE")) {
		if (
			LIMIT_REPLIES.has(reply.code) &&
			reply.enhanced !== undefined &&
			LIMIT_ENHANCED_CODES.has(reply.enhanced)
		) {
			return "refused_at_limit";
		}
		return new MailTransportError(`the relay refused ${stage}`, "rejected", reply);
	}
	if (code === "ETLS") {
		return new MailTransportError(
			"the connection to the relay could not be secured: STARTTLS refused, or the TLS handshake or the relay's certificate",
			"unreachable",
			reply,
		);
	}
	return new MailTransportError(
		"the relay could not be reached, or turned the connection away",
		"unreachable",
		reply,
	);
}
