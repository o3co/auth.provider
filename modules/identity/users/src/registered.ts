import { deepFreeze } from "@mod/kernel";
import { readSecretHash, type SecretChecker, type SecretHash } from "@mod/secret-hash";
import { z } from "zod";
import {
	isAttributeValue,
	isWellFormedSubject,
	type Unanswerable,
	type User,
	type Users,
	type Verified,
} from "./contract.ts";

const upstreamIdentity = z.strictObject({
	idp: z.string().min(1).describe("The name of the upstream identity provider."),
	subject: z.string().min(1).describe("The user's subject at that identity provider."),
});

/** One key per upstream identity, whatever its parts hold. */
export const keyOf = (identity: { readonly idp: string; readonly subject: string }) =>
	JSON.stringify([identity.idp, identity.subject]);

export const record = z
	.strictObject({
		identifier: z.string().min(1).describe("What the user logs in with, matched exactly."),
		subject: z
			.string()
			.min(1)
			.optional()
			.describe("The subject, 1 to 255 ASCII characters; the identifier when left out."),
		"password-hash": z
			.string()
			.refine(
				(s) => readSecretHash(s) !== undefined,
				"a bcrypt or scrypt hash (plaintext is not accepted)",
			)
			.describe("The user's password as a bcrypt or scrypt hash."),
		attributes: z
			.record(z.string(), z.json())
			.superRefine((attributes, context) => {
				for (const [name, value] of Object.entries(attributes)) {
					if (isAttributeValue(name, value)) continue;
					context.addIssue({
						code: "custom",
						message: "not a value this attribute takes",
						path: [name],
					});
				}
			})
			.prefault({})
			.describe("The user's attributes by OIDC claim name, such as `email`, `name` or `groups`."),
		upstream: z
			.array(upstreamIdentity)
			.prefault([])
			.describe("The upstream identities linked to the user."),
	})
	.superRefine((user, context) => {
		// An empty one is refused at its own key already.
		const subject = user.subject ?? user.identifier;
		if (subject === "" || isWellFormedSubject(subject)) return;
		context.addIssue({
			code: "custom",
			message: "1 to 255 ASCII characters (the identifier's, where subject is left out)",
			path: ["subject"],
		});
	});

export const none: Verified = deepFreeze({ kind: "none" });
export const unanswerable: Unanswerable = deepFreeze({ kind: "unanswerable" });

/** Makes the checker for the hashes in use, as `secret-hash`'s checkers do; tests may record the work each check does. */
export type CheckerOf = (inUse: Iterable<SecretHash>) => SecretChecker;

export type UserSource = Pick<Users, "verify" | "bySubject" | "byUpstream">;

/** The users the settings register, checked by a checker `secret-hash` makes for their hashes. */
export function registeredUsers(
	registered: readonly z.output<typeof record>[],
	checkerOf: CheckerOf,
): UserSource {
	const known = new Map<string, { user: User; hash: SecretHash }>();
	const linked = new Map<string, User>();
	const subjects = new Map<string, User>();
	for (const r of registered) {
		const user = deepFreeze({ subject: r.subject ?? r.identifier, attributes: r.attributes });
		// The section refused any other form at boot.
		known.set(r.identifier, { user, hash: readSecretHash(r["password-hash"]) as SecretHash });
		subjects.set(user.subject, user);
		for (const identity of r.upstream) linked.set(keyOf(identity), user);
	}
	// An unknown identifier costs the same work as a known one: the checker computes decoys for it.
	const checker = checkerOf([...known.values()].map(({ hash }) => hash));
	return {
		verify: async (identifier, password) => {
			const found = known.get(identifier);
			const matched = await checker.check(found?.hash, password);
			return found && matched ? { kind: "user", user: found.user } : none;
		},
		byUpstream: async (idp, upstreamSubject) => {
			const user = linked.get(keyOf({ idp, subject: upstreamSubject }));
			return user ? { kind: "user", user } : none;
		},
		bySubject: async (subject) => {
			const user = subjects.get(subject);
			return user ? { kind: "user", user } : none;
		},
	};
}
