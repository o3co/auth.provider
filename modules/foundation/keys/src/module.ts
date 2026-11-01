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
		if ("unreadable" in read) {
			// Its algorithm is the `alg` beside it.
			const alg = `keys.${read.unreadable.replace(/[^.]+$/, "alg")}`;
			return c.refuse(
				`keys.${read.unreadable}`,
				`not readable as a key of the kind ${alg} names: write a PEM key of that kind (the example's REPLACE- placeholder is none)`,
			);
		}
		return read;
	}),
	m.provide(keys).by(async (c) => ({
		...signer(await c.get(ring), c.clock.now, c.log),
		keySetPath: () => keySetPath,
	})),
	m
		.provide(accessTokenSigning)
		.by(async (c) => accessSigner(await c.get(ring), c.clock.now, c.log)),
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
