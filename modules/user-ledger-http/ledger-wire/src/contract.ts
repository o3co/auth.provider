import { z } from "zod";

/** A user as the user ledger answers it, `200` to the password call and to a lookup. */
export interface LedgerUserAnswer {
	/** The subject. */
	readonly id: string;
	/** The identifier the password call checked; its answer names it. */
	readonly username?: string;
	readonly email?: string;
	/** Whether `email` is verified; said beside it alone. */
	readonly emailVerified?: boolean;
	readonly name?: string;
	readonly picture?: string;
	readonly groups?: readonly string[];
}

/** The user ledger's calls, as users-http makes them and a ledger answers them. */
export const usersWire = Object.freeze({
	/** The password call's body: the identifier under the name the ledger reads. */
	verify: (identifier: string, password: string) => ({ email: identifier, password }),
	/** A lookup's body, by subject. */
	bySubject: (subject: string) => ({ subject }),
	/** A lookup's body, by an upstream identity: the IdP's name and the subject there. */
	byUpstream: (idp: string, subject: string) => ({ idp, subject }),
	/** What a lookup's `404` and `410` say in `error` to mean no such user; unsaid, they mean nothing. */
	noUser: Object.freeze({ 404: "not_found", 410: "gone" }) as Readonly<Record<number, string>>,
	/** The password call's answer to a wrong identifier or password; challenging `Bearer`, it refuses the credential. */
	refused: 401,
});

/** A witness ledger's calls, mfa-witness-http's and passkey-witness-http's alike: their bodies and answers. */
export const witnessWire = Object.freeze({
	read: (subject: string) => ({ subject }),
	/** A write's `deadline`: the time (ms since the epoch) past which the provider no longer waits for it. */
	enroll: (subject: string, token: string, deadline: number) => ({ subject, token, deadline }),
	withdraw: (subject: string, token: string, deadline: number) => ({ subject, token, deadline }),
	clear: (subject: string, deadline: number) => ({ subject, deadline }),
	/** A read's answer: whether the subject is marked. */
	readAnswer: z.object({ enrolled: z.boolean() }),
	/** A read's answer where withdraw is offered: a marked one names its mark's token. */
	markAnswer: z.union([
		z.object({ enrolled: z.literal(true), token: z.string().min(1) }),
		z.object({ enrolled: z.literal(false) }),
	]),
	/** An enroll's answer: whether the token sent is the mark's, set now or before. */
	enrollAnswer: z.object({ owner: z.boolean() }),
	/** A write's answer (withdraw, clear) once done. */
	written: 204,
});

/** The routes a fake ledger and the examples serve each call at; a deployment's are its settings' URLs. */
export const ledgerRoutes = Object.freeze({
	users: Object.freeze({ verify: "/verify", subject: "/subject", upstream: "/upstream" }),
	mfaWitness: Object.freeze({
		read: "/mfa-witness/read",
		enroll: "/mfa-witness/enroll",
		clear: "/mfa-witness/clear",
		withdraw: "/mfa-witness/withdraw",
	}),
	passkeyWitness: Object.freeze({
		read: "/passkey-witness/read",
		enroll: "/passkey-witness/enroll",
		withdraw: "/passkey-witness/withdraw",
	}),
});
