import type { UserScene } from "./area.ts";

/** An address for a user the scene gave none: users keeps whether an email is verified only beside one. */
export const addressOf = (user: UserScene) => user.email ?? `${user.identifier}@users.example`;

/**
 * The users on a pattern's app: where it composes verified-email, which refuses tokens to a user not stated
 * verified, a scene that states no user's either way has every user stated verified, with an address.
 */
export function statedWhereJudged(
	users: readonly UserScene[],
	modules: readonly string[],
): readonly UserScene[] {
	const silent = users.every((u) => u.emailVerified === undefined);
	if (!modules.includes("@mod/verified-email") || !silent) return users;
	return users.map((u) => ({ ...u, email: addressOf(u), emailVerified: true }));
}
