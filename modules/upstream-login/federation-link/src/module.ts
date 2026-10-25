import { defineModule } from "@mod/kernel";
import { upstreamContinuations } from "@mod/upstreams";
import { loopbackPagesRefused } from "@mod/url-setting";
import { linkIn, linkTakes } from "./link.ts";
import { name, section } from "./section.ts";

export default defineModule(
	{
		name,
		section,
		refusedInProduction: (s) => loopbackPagesRefused({ "step-up-page": s["step-up-page"] }),
		takes: linkTakes,
	},
	(m) => [m.contribute(upstreamContinuations).by(linkIn)],
);
