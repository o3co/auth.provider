import { defineModule } from "@mod/kernel";
import { mailTemplates, plainText } from "@mod/mail";
import { wordings } from "./wordings.ts";

export default defineModule({ name: "mfa-email-wording", replicaSafe: true }, (m) =>
	Object.entries(wordings).map(([purpose, wording]) =>
		m.contribute(mailTemplates).by(() => plainText(purpose, wording)),
	),
);
