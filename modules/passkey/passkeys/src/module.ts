import { audit } from "@mod/audit";
import { type BuildContext, contract, defineModule } from "@mod/kernel";
import { ceremonies, freshHandle } from "@mod/webauthn";
import { keptChallenges } from "./challenges/challenges.ts";
import {
	challengeStore,
	passkeyHolders,
	passkeyStore,
	passkeys,
	passkeyWitnesses,
	passkeyWitnessing,
	registrations,
} from "./contract.ts";
import { holdersOver } from "./holders/holders.ts";
import { passkeysOver } from "./passkeys.ts";
import { type KeptPasskeys, keptPasskeys } from "./records.ts";
import { registrationsOver } from "./registration/registrations.ts";
import { type Settings, section } from "./section.ts";

type Context = BuildContext<Settings>;
/** A new token: 16 random bytes, unpadded base64url. */
const tokenOf = (c: Context) => () => Buffer.from(c.random.bytes(16)).toString("base64url");
/** The passkey records, made once for the module's parts. */
const kept = contract<KeptPasskeys>("passkeys.records");
const passkeysOf = (c: Context) => c.get(kept);
// A challenge lives as long as the relying party lets one be answered.
const challengesOf = async (c: Context) =>
	keptChallenges(await c.get(challengeStore), c.clock.now, (await c.get(ceremonies)).lifetimeMs);
/** The holdings over the one witness and the one witnessing composed, if any; two of either refuse boot. */
const holdingOf = async (c: Context) => {
	const [witness, ...more] = await c.collect(passkeyWitnesses);
	if (more.length > 0) return { refused: "more than one passkey witness is composed" } as const;
	const [witnessing, ...others] = await c.collect(passkeyWitnessing);
	if (others.length > 0) {
		return { refused: "more than one passkey witnessing is contributed" } as const;
	}
	const holding = holdersOver({
		records: await passkeysOf(c),
		witness,
		witnessing,
		audit: await c.get(audit),
		log: c.log,
		token: tokenOf(c),
		handle: () => freshHandle(c.random.bytes),
	});
	return { holding } as const;
};

export default defineModule({ name: "passkeys", section, replicaSafe: true }, (m) => [
	// Over a store that changes both its spaces as one: typed as required, and checked here for a
	// store built where no type is checked.
	m.provide(kept).by(async (c) => {
		const store = await c.get(passkeyStore);
		if (typeof store.updateTogether !== "function") {
			return c.refuse("passkeys", "its passkey store cannot change both its spaces as one");
		}
		return keptPasskeys(store, tokenOf(c), c.clock.now);
	}),
	m.provide(passkeys).by(async (c) =>
		passkeysOver({
			ceremonies: await c.get(ceremonies),
			records: await passkeysOf(c),
			challenges: await challengesOf(c),
			verification: c.section["user-verification"],
		}),
	),
	m.provide(registrations).by(async (c) => {
		const held = await holdingOf(c);
		if ("refused" in held) return c.refuse("passkeys", held.refused);
		return registrationsOver({
			ceremonies: await c.get(ceremonies),
			records: await passkeysOf(c),
			challenges: await challengesOf(c),
			verification: c.section["user-verification"],
			max: c.section["max-credentials"],
			freshHandle: () => freshHandle(c.random.bytes),
			settle: held.holding.settle,
		});
	}),
	m.provide(passkeyHolders).by(async (c) => {
		const held = await holdingOf(c);
		if ("refused" in held) return c.refuse("passkeys", held.refused);
		return held.holding.holders;
	}),
]);
