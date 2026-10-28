import { routes } from "@mod/http";
import { contract, defineModule } from "@mod/kernel";
import { accessTokenSigning, keys } from "./contract.ts";
import { jwksResponse } from "./jwks/jwks.ts";
import { type Ring, readRing } from "./signing/ring.ts";
import { section } from "./signing/section.ts";
import { accessSigner, signer } from "./signing/signer.ts";

const ring = contract<Ring>("keys.ring");
const keySetPath = "/.well-known/jwks.json";

// Safe on many instances given the same keys on each (deployment-guarantees, Several instances).
export default defineModule({ name: "keys", replicaSafe: true, section, takes: [] }, (m) => [
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
	m.provide(accessTokenSigning).by(async (c) => accessSigner(await c.get(ring), c.clock.now)),
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
