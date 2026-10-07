/**
 * `webauthnSessionSubjectModule`: sets `req.webauthnSubject`, which both
 * registration routes require, from the browser's cookie session, admitted as
 * `webauthn.register` (graded `credential_change`: a passkey is a new way
 * into the account), once the request body has arrived. What it needs,
 * where it runs and what each admission outcome answers are in the README,
 * "Registering from a browser session"; see also ADR
 * 2026-09-28-session-admission.
 */
import { type Module, type UserSession } from "@o3co/auth-provider-core";
import type { WebAuthnSubject } from "./request.mjs";
/** The id of the module's one route. */
export declare const WEBAUTHN_SESSION_SUBJECT_ROUTE_ID = "webauthn-session-subject";
/** What the deployment gives the module. */
export interface WebAuthnSessionSubjectOptions {
    /**
     * The WebAuthn subject for an admitted session — synchronous, called with
     * the live `UserSession` admission read. `userId` is the user handle an
     * authenticator stores and may sync: opaque, 1–64 bytes, never an e-mail
     * or a username (WebAuthn §5.4.3; the README's "`userId` opacity"), and
     * not guessable where the RP ID is shared with another system (the
     * README's "Known limitations").
     */
    readonly subjectFor: (session: UserSession) => WebAuthnSubject;
}
/** What registering from a session admits: a passkey is a new way into the account. */
export declare const SESSION_SUBJECT_ADMISSION_ACTIONS: Readonly<{
    readonly "webauthn.register": Readonly<{
        grade: "credential_change";
    }>;
}>;
/**
 * The module: requires the resolver and the user-session store, and core's
 * session lifecycle port (`sessionLifecycleStore`) beside the store; takes
 * `subjectRevocation`, `auditSink` and `logger` when they are wired, the
 * first two under their shared absence policies. Throws a `TypeError` when
 * `subjectFor` is not a function, and its route factory a `RangeError` for a
 * resolver missing or not the planner's (core's `checkResolver`), and an
 * `Error` for a missing lifecycle port.
 */
export declare function webauthnSessionSubjectModule(options: WebAuthnSessionSubjectOptions): Module;
//# sourceMappingURL=sessionSubject.d.mts.map