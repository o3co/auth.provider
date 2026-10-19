import { defineModule } from "@mod/kernel";
import { factorKinds } from "@mod/mfa-extensions";
import { subjectAttributes } from "@mod/subject-attributes";
import { ceremonies } from "@mod/webauthn";
import { webauthnKind } from "./kind.ts";
import { section } from "./section.ts";

export default defineModule({ name: "mfa-webauthn", section, replicaSafe: true }, (m) => [
	m.contribute(factorKinds).by(async (c) =>
		webauthnKind({
			ceremonies: await c.get(ceremonies),
			verification: c.section["user-verification"],
			// Read at enrolment: subject-attributes reads sessions, whose requirements read factor kinds.
			attributes: c.late(subjectAttributes),
			displayName: c.section["display-name"],
			random: c.random.bytes,
		}),
	),
]);
