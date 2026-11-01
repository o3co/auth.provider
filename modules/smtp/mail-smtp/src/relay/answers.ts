import { getSystemErrorName } from "node:util";

/** Where a send stopped. */
export type Stage =
	| "address"
	| "connection"
	| "security"
	| "greeting"
	| "account"
	| "sender"
	| "recipient"
	| "message"
	| "deadline";

export interface FailureCodes {
	/** The relay's reply code (RFC 5321). */
	readonly reply?: number;
	/** The reply's enhanced status code (RFC 3463). */
	readonly enhanced?: string;
	/** A connection failure from `TRANSPORT_CODES`. */
	readonly code?: string;
	/** The TLS alert that refused the handshake (RFC 8446 §6), its number as OpenSSL reports it. */
	readonly alert?: number;
}

/** A send the relay did not accept. It holds the stage and codes only, never the relay's words. */
export class RelayFailure extends Error {
	readonly stage: Stage;
	readonly codes: FailureCodes;
	constructor(stage: Stage, codes: FailureCodes = {}) {
		const shown = [codes.reply, codes.enhanced, codes.code, codes.alert].filter(
			(v) => v !== undefined,
		);
		super(`relay failed at ${stage}${shown.length > 0 ? ` (${shown.join(" ")})` : ""}`);
		this.name = "RelayFailure";
		this.stage = stage;
		this.codes = Object.freeze({ ...codes });
	}
}

const TRANSPORT_CODES = new Set([
	"ECONNREFUSED",
	"ECONNRESET",
	"ENOTFOUND",
	"EAI_AGAIN",
	"EHOSTUNREACH",
	"ENETUNREACH",
	"ETIMEDOUT",
]);

/** The command each stage of the mail itself answers. */
const MAIL_STAGES: ReadonlyMap<string, Stage> = new Map([
	["MAIL FROM", "sender"],
	["RCPT TO", "recipient"],
	["DATA", "message"],
]);

/** A limit: one of these replies to the mail itself, with one of these enhanced codes. */
const LIMIT_REPLIES = new Set([421, 450, 451, 452]);
const LIMIT_ENHANCED = new Set(["4.7.1", "4.7.28", "4.5.3"]);

/** A refused handshake's TLS alert, ending OpenSSL's error; never of a reply, whose words the library adds. */
function alertOf(failure: unknown): number | undefined {
	const code = stringField(failure, "code") ?? "";
	if (stringField(failure, "response") !== undefined) return undefined;
	if (code !== "ETLS" && code !== "ESOCKET" && !code.startsWith("ERR_SSL_")) return undefined;
	const alert = /SSL alert number (\d{1,3})\s*$/.exec(stringField(failure, "message") ?? "")?.[1];
	return alert !== undefined && Number(alert) <= 255 ? Number(alert) : undefined;
}

/** A reply's code, and an enhanced code of the same class right after it. */
const REPLY =
	/^(?<replyClass>[2-5])\d\d(?:[ -](?<enhancedClass>[2-5])\.(?<subject>\d{1,3})\.(?<detail>\d{1,3})(?=[ \r\n]|$))?/;

function field(value: unknown, key: string): unknown {
	return typeof value === "object" && value !== null
		? (value as Record<string, unknown>)[key]
		: undefined;
}

function stringField(value: unknown, key: string): string | undefined {
	const found = field(value, key);
	return typeof found === "string" ? found : undefined;
}

/** The connection failure's code when it is a listed one; the library may keep it only as errno. */
export function transportCode(failure: unknown): string | undefined {
	const code = stringField(failure, "code");
	if (code !== undefined && TRANSPORT_CODES.has(code)) return code;
	const errno = field(failure, "errno");
	if (typeof errno !== "number" || !Number.isInteger(errno) || errno >= 0) return undefined;
	try {
		const name = getSystemErrorName(errno);
		return TRANSPORT_CODES.has(name) ? name : undefined;
	} catch {
		return undefined;
	}
}

function replyCodes(response: string | undefined): FailureCodes {
	const match = response === undefined ? null : REPLY.exec(response);
	if (match === null) return {};
	const { replyClass, enhancedClass, subject, detail } = match.groups ?? {};
	const reply = Number(match[0].slice(0, 3));
	if (enhancedClass === undefined || enhancedClass !== replyClass) return { reply };
	return { reply, enhanced: `${enhancedClass}.${Number(subject)}.${Number(detail)}` };
}

/** Where the connection was when it failed: being secured, or connected but not yet greeted. */
export interface Phase {
	readonly securing: boolean;
	readonly awaitingGreeting: boolean;
}

function stageOf(command: string | undefined, code: string | undefined, phase: Phase): Stage {
	const mail = MAIL_STAGES.get(command ?? "");
	if (mail !== undefined) return mail;
	if (command?.startsWith("AUTH") || code === "EAUTH") return "account";
	if (phase.securing || code === "ETLS" || command === "STARTTLS") return "security";
	if (command === "EHLO" || command === "HELO" || code === "EPROTOCOL") return "greeting";
	// The library names a greeting that never came a connection failure (`CONN`).
	if (phase.awaitingGreeting) return "greeting";
	return "connection";
}

/** A limit: a limit reply, with a limit enhanced code, to the mail itself (its envelope or data). */
function isLimit(stage: Stage, libraryCode: string | undefined, codes: FailureCodes): boolean {
	const isMail = stage === "sender" || stage === "recipient" || stage === "message";
	const toMail = libraryCode === "EENVELOPE" || libraryCode === "EMESSAGE";
	return (
		isMail &&
		toMail &&
		codes.reply !== undefined &&
		LIMIT_REPLIES.has(codes.reply) &&
		codes.enhanced !== undefined &&
		LIMIT_ENHANCED.has(codes.enhanced)
	);
}

/**
 * What the library failed with, as the sender answers it: limited, or a RelayFailure. Only a
 * limit reply to the mail itself is limited; any reply while connecting, greeting, securing or
 * signing in is a failure.
 */
export function answerOf(failure: unknown, phase: Phase): "limited" | RelayFailure {
	if (failure instanceof RelayFailure) return failure;
	const libraryCode = stringField(failure, "code");
	const stage = stageOf(stringField(failure, "command"), libraryCode, phase);
	const reply = replyCodes(stringField(failure, "response"));
	if (isLimit(stage, libraryCode, reply)) return "limited";
	const transport = transportCode(failure);
	const alert = alertOf(failure);
	return new RelayFailure(stage, {
		...reply,
		...(transport !== undefined && { code: transport }),
		...(alert !== undefined && { alert }),
	});
}
