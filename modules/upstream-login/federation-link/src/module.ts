import { defineModule } from "@mod/kernel";
import { upstreamContinuations } from "@mod/upstreams";
import { linkIn, linkTakes } from "./link.ts";
import { name, section } from "./section.ts";

export default defineModule({ name, section, takes: linkTakes }, (m) => [
	m.contribute(upstreamContinuations).by(linkIn),
]);
