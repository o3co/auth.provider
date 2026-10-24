import { defineModule } from "@mod/kernel";
import { type Entry, sessions } from "@mod/session";
import { users } from "@mod/users";
import { type AttributesAnswer, subjectAttributes, vouches } from "./contract.ts";

const neither: AttributesAnswer = Object.freeze({ kind: "unknown" });
const noAttributes = Object.freeze({});

/** The login attributes a session kept, under its source, when the subject's session enters at use. */
const fromLogin = (subject: string, entry: Entry): AttributesAnswer => {
	// Absent or short of a requirement: no session to read the login from.
	if (entry.kind !== "entered") return neither;
	const { context } = entry.session;
	return context.subject !== subject || context.attributes === undefined
		? neither
		: {
				kind: "known",
				vouched: vouches(context.attributes),
				attributes: Object.freeze({ ...context.attributes.values }),
			};
};

export default defineModule({ name: "subject-attributes", takes: [sessions, users] }, (m) => [
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
							vouched: true,
							attributes: found.user.attributes,
						};
					case "none":
						return {
							kind: "known",
							vouched: true,
							attributes: noAttributes,
						};
					case "unanswerable":
						// Only when users cannot say: the login the session kept, if it is the subject's.
						return handle === undefined ? neither : fromLogin(subject, await open.entryOf(handle));
				}
			},
		};
	}),
]);
