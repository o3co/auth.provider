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
 * A `MailTransportError` is built from a closed reason, the stage, the
 * reply's codes and a transport code from a short list alone: never the
 * reply's text or the transport's, which can quote the recipient, the code
 * or the credentials, and never a `cause`.
 */
import { getSystemErrorName } from "node:util";
/**
 * A send the SMTP sender could not make. `name`, `reason`, `replyCode`,
 * `enhancedCode` and `code` are part of the contract; the message names the
 * stage, the reply's codes and the transport's code, and nothing the relay
 * or the transport wrote.
 */
export class MailTransportError extends Error {
    reason;
    /** The relay's reply code (RFC 5321 §4.2), when the failure was a reply. */
    replyCode;
    /** The reply's enhanced status code (RFC 3463), when it carried one. */
    enhancedCode;
    /** The connection's failure, when it is one of `TRANSPORT_CODES` (`ECONNREFUSED`, …). */
    code;
    constructor(what, reason, details = {}) {
        const { reply, code } = details;
        const replied = reply === undefined
            ? ""
            : ` (SMTP ${reply.code}${reply.enhanced === undefined ? "" : ` ${reply.enhanced}`})`;
        super(`standard-smtp-mail-sender: ${what}${replied}${code === undefined ? "" : ` (${code})`}`);
        this.name = "MailTransportError";
        this.reason = reason;
        this.replyCode = reply?.code;
        this.enhancedCode = reply?.enhanced;
        this.code = code;
    }
}
/** The connection failures an operator can act on, kept by their code. */
const TRANSPORT_CODES = new Set([
    "ECONNREFUSED",
    "ENOTFOUND",
    "EAI_AGAIN",
    "EHOSTUNREACH",
    "ENETUNREACH",
    "ECONNRESET",
]);
/** A reply's first line: its code, and the enhanced code of the same class after it. */
const REPLY = /^([2-5])\d\d(?:[ -]([2-5])\.(\d{1,3})\.(\d{1,3})(?=[ \r\n]|$))?/;
/** The codes of `response`, a reply as the transport kept it, or none. */
function replyCodesOf(response) {
    if (typeof response !== "string")
        return undefined;
    const match = REPLY.exec(response);
    if (match === null)
        return undefined;
    const [whole, replyClass, enhancedClass, subject, detail] = match;
    const code = Number(whole.slice(0, 3));
    const enhanced = enhancedClass === replyClass && enhancedClass !== undefined
        ? `${enhancedClass}.${Number(subject)}.${Number(detail)}`
        : undefined;
    return { code, enhanced };
}
/** The transport's commands a refusal of this mail answers, as the stage the error names. */
const MAIL_STAGES = {
    "MAIL FROM": "the sender",
    "RCPT TO": "the recipient",
    DATA: "the message",
};
const LIMIT_REPLIES = new Set([421, 450, 451, 452]);
const LIMIT_ENHANCED_CODES = new Set(["4.7.1", "4.7.28", "4.5.3"]);
/** A string property of `value`, or none. */
const stringOf = (value, key) => {
    if (typeof value !== "object" || value === null)
        return undefined;
    const property = value[key];
    return typeof property === "string" ? property : undefined;
};
/** A number property of `value`, or none. */
const numberOf = (value, key) => {
    if (typeof value !== "object" || value === null)
        return undefined;
    const property = value[key];
    return typeof property === "number" ? property : undefined;
};
/**
 * The transport code of `failure`, when it is one of `TRANSPORT_CODES`: its
 * `code`, or the system error its `errno` names (the transport replaces a
 * socket error's `code` with its own).
 */
export function transportCodeOf(failure) {
    const code = stringOf(failure, "code");
    if (code !== undefined && TRANSPORT_CODES.has(code))
        return code;
    const errno = numberOf(failure, "errno");
    if (errno === undefined || !Number.isInteger(errno) || errno >= 0)
        return undefined;
    try {
        const name = getSystemErrorName(errno);
        return TRANSPORT_CODES.has(name) ? name : undefined;
    }
    catch {
        return undefined;
    }
}
/**
 * `failure`, what the SMTP exchange failed with, as the sender answers it:
 * `refused_at_limit`, or the `MailTransportError` it rejects with. `securing`
 * says the connection was being secured when it failed.
 */
export function readSendFailure(failure, securing = false) {
    const code = stringOf(failure, "code");
    const stage = MAIL_STAGES[stringOf(failure, "command") ?? ""];
    const reply = replyCodesOf(stringOf(failure, "response"));
    if (code === "ETIMEDOUT")
        return new MailTransportError("the relay did not answer in time", "timeout");
    if (code === "EAUTH") {
        return new MailTransportError("the relay refused the account's credentials", "auth_failed", {
            reply,
        });
    }
    if (stage !== undefined && reply !== undefined && (code === "EENVELOPE" || code === "EMESSAGE")) {
        if (LIMIT_REPLIES.has(reply.code) &&
            reply.enhanced !== undefined &&
            LIMIT_ENHANCED_CODES.has(reply.enhanced)) {
            return "refused_at_limit";
        }
        return new MailTransportError(`the relay refused ${stage}`, "rejected", { reply });
    }
    const details = { reply, code: transportCodeOf(failure) };
    if (securing || code === "ETLS") {
        return new MailTransportError("the connection to the relay could not be secured: STARTTLS refused, or the TLS handshake or the relay's certificate", "unreachable", details);
    }
    return new MailTransportError("the relay could not be reached, or turned the connection away", "unreachable", details);
}
