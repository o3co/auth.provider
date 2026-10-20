import { cookies } from "@mod/cookies";
import { jsonAnswer, routes } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { carried, keptToken, newToken } from "./check.ts";
import { deciding } from "./deciding.ts";

const tokenSeconds = 7200;

export default defineModule({ name: "csrf" }, (m) => [
	...deciding(m, "refuse boot"),
	m.contribute(routes).by(async (c) => {
		const jar = await c.get(cookies);
		return {
			method: "GET",
			changesState: false,
			path: "/session/csrf",
			handle: (request) => {
				// A valid token is kept, so forms open in other tabs stay usable.
				const token = keptToken(jar, request) ?? newToken(c.random);
				return jsonAnswer(
					200,
					{
						csrf_token: token,
						header_name: carried.header,
						body_field: carried.field,
						expires_in: tokenSeconds,
					},
					{ cookies: [jar.write(carried.cookie, token, tokenSeconds)] },
				);
			},
		};
	}),
]);
