import { defineModule } from "@mod/kernel";
import { type AuthContext, sessions } from "@mod/session";
import { users } from "@mod/users";
import {
	type AttributesAnswer,
	type AttributesSource,
	subjectAttributes,
	vouches,
} from "./contract.ts";

const fromUsers: AttributesSource = "users";
const neither: AttributesAnswer = Object.freeze({ kind: "unknown" });
const noAttributes = Object.freeze({});

/** The login attributes a session kept, under its source, when it is the subject's open session. */
const fromLogin = (subject: string, context: AuthContext | undefined): AttributesAnswer =>
	context?.subject !== subject || context.attributes === undefined
		? neither
		: {
				kind: "known",
				source: `session:${context.attributes.source}`,
				vouched: vouches(context.attributes),
				attributes: Object.freeze({ ...context.attributes.values }),
			};

export default defineModule({ name: "subject-attributes" }, (m) => [
	m.provide(subjectAttributes).by(async (c) => {
		const known = await c.get(users);
		const open = await c.get(sessions);
		return {
			of: async (subject, handle) => {
				const found = await known.bySubject(subject);
				switch (found.kind) {
					case "user":
						return {
							kind: "known",
							source: fromUsers,
							vouched: true,
							attributes: found.user.attributes,
						};
					case "none":
						return {
							kind: "known",
							source: fromUsers,
							vouched: true,
							attributes: noAttributes,
						};
					case "unanswerable":
						// Only when users cannot say: the login the session kept, if it is the subject's.
						return handle === undefined
							? neither
							: fromLogin(subject, await open.openContext(handle));
				}
			},
		};
	}),
]);
