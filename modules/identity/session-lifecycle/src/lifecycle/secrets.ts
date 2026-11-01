import type { Cookies } from "@mod/cookies";
import type { HttpRequest } from "@mod/http";
import { type Random, Unavailable } from "@mod/kernel";
import type { CookieIndex } from "../store.ts";

/** A session cookie's secret, and a session's handle: 32 random bytes in base64url, 43 characters. */
export const freshToken = (random: Random) => Buffer.from(random.bytes(32)).toString("base64url");
const secretShape = /^[A-Za-z0-9_-]{43}$/;

export function secretsWith(parts: {
	readonly jar: Cookies;
	readonly index: CookieIndex;
	readonly random: Random;
}) {
	const { jar, index, random } = parts;
	const secretIn = (request: HttpRequest) => {
		const carried = jar.lookup(request, "session");
		return carried.kind === "found" && secretShape.test(carried.value) ? carried.value : undefined;
	};
	return {
		secretIn,
		handleIn: async (request: HttpRequest) => {
			const secret = secretIn(request);
			return secret ? index.read(secret) : undefined;
		},
		issueSecret: async (handle: string, forMs: number) => {
			const secret = freshToken(random);
			if ((await index.save(secret, handle, forMs)) !== "created") throw new Unavailable("session");
			return { cookie: jar.write("session", secret, Math.max(1, Math.floor(forMs / 1000))) };
		},
		retireSecret: (secret: string) => index.remove(secret),
	};
}
