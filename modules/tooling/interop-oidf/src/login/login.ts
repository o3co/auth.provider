/** What the front answers the browser. */
export interface PageAnswer {
	readonly status: number;
	readonly headers: { readonly location?: string; readonly "set-cookie"?: readonly string[] };
	readonly body: string;
}

const escaped = (text: string) =>
	text
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;");

const page = (redirectTo: string | null, refusal?: string) => `<!doctype html>
<html><head><meta charset="utf-8"><title>Log in</title></head><body>
${refusal === undefined ? "" : `<p role="alert">${escaped(refusal)}</p>\n`}<form method="post" action="/login">
<label>User <input type="text" name="username" autocomplete="username"></label>
<label>Password <input type="password" name="password" autocomplete="current-password"></label>
${redirectTo === null ? "" : `<input type="hidden" name="redirect_to" value="${escaped(redirectTo)}">\n`}<button type="submit" name="login">Log in</button>
</form></body></html>
`;

/**
 * The deployment's login page as the suite's browser meets it: a form with no script, whose
 * answer the page itself takes to the provider's password login, as the browser at its address,
 * and turns into the redirect the provider names, with the session it set.
 */
export function loginPage(upstream: string, publicOrigin: string) {
	return {
		form: (redirectTo: string | null) => page(redirectTo),
		async submit(
			form: URLSearchParams,
			browser: { readonly cookie?: string; readonly address: string },
		): Promise<PageAnswer> {
			const redirectTo = form.get("redirect_to");
			const sent = new URLSearchParams({
				username: form.get("username") ?? "",
				password: form.get("password") ?? "",
				...(redirectTo === null ? {} : { redirect_to: redirectTo }),
			});
			const answer = await fetch(`${upstream}/session/login`, {
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					origin: publicOrigin,
					"x-forwarded-proto": "https",
					"x-forwarded-for": browser.address,
					...(browser.cookie === undefined ? {} : { cookie: browser.cookie }),
				},
				body: sent,
				redirect: "manual",
			});
			const body = (await answer.json().catch(() => ({}))) as {
				readonly redirect_to?: string;
				readonly error?: string;
			};
			const cookies = answer.headers.getSetCookie();
			const session = cookies.length > 0 ? { "set-cookie": cookies } : {};
			if (!answer.ok) {
				return {
					status: answer.status,
					headers: session,
					body: page(redirectTo, body.error ?? `refused (${answer.status})`),
				};
			}
			if (typeof body.redirect_to !== "string") {
				return { status: 200, headers: session, body: "<!doctype html><p>Logged in.</p>\n" };
			}
			return { status: 302, headers: { location: body.redirect_to, ...session }, body: "" };
		},
	};
}

export type LoginPage = ReturnType<typeof loginPage>;
