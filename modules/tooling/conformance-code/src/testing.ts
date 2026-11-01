/** What the deployment's proxy adds to a client's own call, such as one to the token endpoint. */
export const backChannel = { "x-forwarded-proto": "https", "x-forwarded-for": "198.51.100.21" };

/** The JSON body of an answer a set-up needs to succeed; any other fails the scene there, naming
 * what answered, its status and its body's start, so an outage reads as one. */
export async function succeeded(res: Response, what: string): Promise<Record<string, unknown>> {
	const text = await res.text();
	if (!res.ok) throw new Error(`${what} answered ${res.status}: ${text.slice(0, 200)}`);
	return (text ? JSON.parse(text) : {}) as Record<string, unknown>;
}

/**
 * A browser behind the deployment's proxy, holding one login's session cookie, from `source`: one
 * address unless a scene's browsers are to be counted apart from the others' per source.
 */
export function browserAt(
	base: () => string,
	issuer: string,
	user: { username: string; password: string },
	source = "198.51.100.20",
) {
	let cookie = "";
	const headers = (extra: Record<string, string> = {}) => ({
		"x-forwarded-proto": "https",
		"x-forwarded-for": source,
		"x-forwarded-host": new URL(issuer).host,
		...extra,
	});
	const login = async () => {
		if (cookie) return cookie;
		const res = await fetch(`${base()}/session/login`, {
			method: "POST",
			headers: headers({ "content-type": "application/x-www-form-urlencoded", origin: issuer }),
			body: new URLSearchParams(user),
		});
		cookie =
			res.headers
				.getSetCookie()
				.map((c) => c.split(";")[0] ?? "")
				.find((c) => /session=/.test(c) && !/csrf/.test(c)) ?? "";
		// A login that failed fails the scene here, not later as a code never given.
		if (!cookie && !res.ok) await succeeded(res, "the login");
		return cookie;
	};
	const authorize = async (params: Record<string, string> | string, withSession = true) => {
		const query = typeof params === "string" ? params : new URLSearchParams(params).toString();
		const res = await fetch(`${base()}/oauth/authorize?${query}`, {
			redirect: "manual",
			headers: headers(withSession ? { cookie: await login() } : {}),
		});
		const location = res.headers.get("location") ?? "";
		return {
			status: res.status,
			at: location ? new URL(location, issuer) : undefined,
			text: await res.text(),
		};
	};
	/** Logs out with the double-submit token, which every target accepts, and drops the cookie. */
	const logout = async () => {
		const session = await login();
		const issued = await fetch(`${base()}/session/csrf`, { headers: headers({ cookie: session }) });
		const csrf = issued.headers.getSetCookie().map((c) => c.split(";")[0] ?? "")[0] ?? "";
		const { csrf_token: token = "" } = (await issued.json()) as { csrf_token?: string };
		const res = await fetch(`${base()}/session/logout`, {
			method: "POST",
			headers: headers({ cookie: `${session}; ${csrf}`, origin: issuer, "x-csrf-token": token }),
		});
		cookie = "";
		return res.status;
	};
	return {
		headers,
		login,
		authorize,
		logout,
		/** Drops the session cookie, so the next login starts a new session. */
		forget: () => {
			cookie = "";
		},
	};
}
