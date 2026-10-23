import { defineModule } from "@mod/kernel";
import { upstreamContinuations } from "@mod/upstreams";
import { linkIn } from "./link.ts";
import { name, section } from "./section.ts";

export default defineModule({ name, section }, (m) => [
	m.contribute(upstreamContinuations).by(linkIn),
]);
