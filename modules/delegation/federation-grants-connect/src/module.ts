import { grantsBrowsers } from "@mod/federation-grants";
import { defineModule } from "@mod/kernel";
import { loopbackPagesRefused } from "@mod/url-setting";
import { connectOver, connectTakes } from "./connect/connect.ts";
import { name, section } from "./section.ts";

export default defineModule(
	{
		name,
		replicaSafe: true,
		section,
		refusedInProduction: (s) =>
			loopbackPagesRefused({
				page: s.page,
				"login-page": s["login-page"],
				"step-up-page": s["step-up-page"],
			}),
		takes: connectTakes,
	},
	(m) => [m.contribute(grantsBrowsers).by(connectOver)],
);
