import { routes } from "@mod/http";
import { contract, defineModule } from "@mod/kernel";
import { keys } from "./contract.ts";
import { jwksResponse } from "./jwks.ts";
import { type Ring, readRing } from "./ring.ts";
import { section } from "./section.ts";
import { signer } from "./signer.ts";

const ring = contract<Ring>("keys.ring");
const keySetPath = "/.well-known/jwks.json";

export default defineModule({ name: "keys", section }, (m) => [
	m.provide(ring).by((c) => {
		const read = readRing(c.section);
		if ("unreadable" in read)
			return c.refuse(`keys.${read.unreadable}`, "not readable as a key for alg");
		return read;
	}),
	m.provide(keys).by(async (c) => ({
		...signer(await c.get(ring), c.clock.now),
		keySetPath: () => keySetPath,
	})),
	m.contribute(routes).by(async (c) => {
		const current = await c.get(ring);
		return {
			method: "GET",
			changesState: false,
			path: keySetPath,
			// Public keys a page may read from any listed origin.
			cors: {},
			handle: (request) => jwksResponse(current, c.clock.now(), request),
		};
	}),
]);
