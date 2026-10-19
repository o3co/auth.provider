import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { contract, extensionPoint } from "@mod/kernel";
import type { SourcedAttributes } from "@mod/login-attributes";

export interface AuthContext {
	readonly subject: string;
	readonly amr: readonly string[];
	/** Epoch ms; when the session opened if the authentication time is unknown. */
	readonly authenticatedAt: number;
	/** No login vouched for the authentication time: never count this session as freshly authenticated. */
	readonly authenticatedAtUnknown?: true;
	/** When the session was last raised, on the kernel's clock (epoch ms); the authentication time stays. */
	readonly raisedAt?: number;
	/** What the last raise added. */
	readonly raisedAmr?: readonly string[];
	/** What the login said of the user, as it was at login. */
	readonly attributes?: SourcedAttributes;
}

export interface LoginFacts {
	readonly subject: string;
	readonly amr: readonly string[];
	/** When the user authenticated (epoch ms), or "unknown"; the opening when later. */
	readonly authenticatedAt: number | "unknown";
	readonly attributes?: SourcedAttributes;
}

export interface Session {
	readonly id: string;
	readonly context: AuthContext;
}

/** What a requirement that falls short answers, passed on unread: any JSON value. */
export type Answer =
	| null
	| boolean
	| number
	| string
	| readonly Answer[]
	| { readonly [key: string]: Answer };

/** How much a request asks of a session: to use it, nothing it grants, to change credentials. */
export type EntryLevel = "use" | "none" | "credentials";

export type Entry =
	| { readonly kind: "entered"; readonly session: Session; readonly endsAt: number }
	| { readonly kind: "absent" }
	/** A requirement is not met; its `answer` is for the client and is passed on unread. */
	| { readonly kind: "short"; readonly requirement: string; readonly answer: Answer };

/** The answer to an entry that did not enter: absent is 401 `login_required`; short is 403 with the requirement's answer. */
export const refusedEntry = (entry: Exclude<Entry, { kind: "entered" }>): HttpResponse =>
	entry.kind === "absent"
		? jsonAnswer(401, { error: "login_required" })
		: jsonAnswer(403, entry.answer);

export interface Sessions {
	enter(request: HttpRequest): Promise<Session | undefined>;
	enterFor(request: HttpRequest, level: EntryLevel): Promise<Entry>;
	/** The entry a request carrying this session's cookie would get at `level` (`use` unless said): entered with its end, short of a requirement, or absent once closed, ended or revoked. */
	entryOf(handle: string, level?: EntryLevel): Promise<Entry>;
	complete(
		request: HttpRequest,
		facts: LoginFacts,
	): Promise<{ readonly session: Session; readonly cookies: readonly string[] }>;
	/** Adds to the request's session what a further authentication proved, under a new cookie. */
	raise(
		request: HttpRequest,
		amr: readonly string[],
	): Promise<
		| {
				readonly session: Session;
				readonly cookies: readonly string[];
				/** False when the old cookie was retired but the raise could not be written: try again. */
				readonly raised: boolean;
		  }
		| undefined
	>;
	closeRequest(request: HttpRequest): Promise<CloseOutcome>;
	close(id: string, request?: HttpRequest): Promise<CloseOutcome>;
	/**
	 * Whether an authentication at `at` (epoch ms, `kernel`'s clock) is still recent: the one window
	 * every recent-authentication check counts in. The checker passes the time of what it judges.
	 */
	recent(at: number): boolean;
}

/** The longest window `recent` may count in. */
export const longestRecentMs = 3_600_000;

/** What a close answers: closed, or pending while a participant has not finished. */
export interface CloseOutcome {
	readonly kind: "closed" | "pending";
	readonly cookies: readonly string[];
	/** The session the close moved, by its handle and subject; none when no record was left to read. */
	readonly session?: { readonly id: string; readonly subject: string };
}

export interface Participant {
	readonly name: string;
	closing(session: Session): Promise<void>;
}

export const sessions = contract<Sessions>("session");

/** What a session must meet to be entered at a level, contributed by the module that owns the rule. */
export interface EntryRequirement {
	readonly name: string;
	/** The levels it judges; where none judges `credentials`, `session`'s floor does. */
	readonly judges: readonly EntryLevel[];
	admits(
		context: AuthContext,
		level: EntryLevel,
	): Promise<{ readonly kind: "admit" } | { readonly kind: "short"; readonly answer: Answer }>;
}

export const entryRequirements = extensionPoint<EntryRequirement>("session.entry-requirements", {
	multiplicity: "keyed",
	keyOf: (requirement) => requirement.name,
});

export const participants = extensionPoint<Participant>("session.participants", {
	multiplicity: "keyed",
	keyOf: (participant) => participant.name,
});
export { sessionRules } from "./rules/rules.ts";
