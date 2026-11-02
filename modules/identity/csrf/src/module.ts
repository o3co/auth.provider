import { cookies } from "@mod/cookies";
import { jsonAnswer, routes } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { carried, issuing, tokenSeconds } from "./check.ts";
import { deciding, decidingTakes } from "./deciding.ts";

export default defineModule({ name: "csrf", replicaSafe: true, takes: decidingTakes }, (m) => [
	...deciding(m, "refuse boot"),
	m.contribute(routes).by(async (c) => {
		const issue = issuing(await c.get(cookies), c.random);
		return {
			method: "GET",
			changesState: false,
			path: "/session/csrf",
			handle: (request) => {
				// A valid token is kept, so forms open in other tabs stay usable.
				const { token, cookie } = issue(request);
				return jsonAnswer(
					200,
					{
						csrf_token: token,
						header_name: carried.header,
						body_field: carried.field,
						expires_in: tokenSeconds,
					},
					{ cookies: [cookie] },
				);
			},
		};
	}),
]);
