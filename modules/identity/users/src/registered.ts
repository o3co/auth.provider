import { deepFreeze, type Random } from "@mod/kernel";
import {
	readSecretHash,
	type SecretChecker,
	type SecretHash,
	secretChecker,
} from "@mod/secret-hash";
import { z } from "zod";
import {
	isAttributeValue,
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

export const record = z.strictObject({
	identifier: z.string().min(1).describe("What the user logs in with, matched exactly."),
	subject: z.string().min(1).optional().describe("The subject; the identifier when left out."),
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
});

export const none: Verified = deepFreeze({ kind: "none" });
export const unanswerable: Unanswerable = deepFreeze({ kind: "unanswerable" });

/** Makes the checker for the hashes in use; tests may record the work each check does. */
export type CheckerOf = (inUse: Iterable<SecretHash>, random: Random["bytes"]) => SecretChecker;

export interface UserSource extends Pick<Users, "verify" | "bySubject" | "byUpstream"> {
	readonly upstreamLast?: true;
}

/** The users the settings register, checked by `secret-hash` with decoys drawn from `random`. */
export function registeredUsers(
	registered: readonly z.output<typeof record>[],
	random: Random["bytes"],
	checkerOf: CheckerOf = secretChecker,
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
	const checker = checkerOf(
		[...known.values()].map(({ hash }) => hash),
		random,
	);
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
