import { defineModule } from "@mod/kernel";
import { upstreamContinuations } from "@mod/upstreams";
import { linkIn } from "./link.ts";

export default defineModule({ name: "federation-link" }, (m) => [
	m.contribute(upstreamContinuations).by(linkIn),
]);
