import { audit } from "@mod/audit";
import { type BuildContext, defineModule } from "@mod/kernel";
import { ceremonies, freshHandle } from "@mod/webauthn";
import {
	challengeStore,
	passkeyHolders,
	passkeyStore,
	passkeys,
	passkeyWitnesses,
	registrations,
} from "./contract.ts";
import { holdersOver } from "./holders/holders.ts";
import { passkeysOver } from "./passkeys.ts";
import { keptChallenges, keptPasskeys } from "./records.ts";
import { registrationsOver } from "./registration/registrations.ts";
import { type Settings, section } from "./section.ts";

type Context = BuildContext<Settings>;
/** A new token: 16 random bytes, unpadded base64url. */
const tokenOf = (c: Context) => () => Buffer.from(c.random.bytes(16)).toString("base64url");
const passkeysOf = async (c: Context) =>
	keptPasskeys(await c.get(passkeyStore), tokenOf(c), c.clock.now);
// A challenge lives as long as the relying party lets one be answered.
const challengesOf = async (c: Context) =>
	keptChallenges(await c.get(challengeStore), c.clock.now, (await c.get(ceremonies)).lifetimeMs);
/** The holdings over the one witness composed, if any; two refuse boot. */
const holdingOf = async (c: Context) => {
	const [witness, ...more] = await c.collect(passkeyWitnesses);
	if (more.length > 0) return undefined;
	return holdersOver({
		records: await passkeysOf(c),
		witness,
		audit: await c.get(audit),
		log: c.log,
		token: tokenOf(c),
	});
};
const twoWitnesses = "more than one passkey witness is composed";

export default defineModule({ name: "passkeys", section, replicaSafe: true }, (m) => [
	m.provide(passkeys).by(async (c) =>
		passkeysOver({
			ceremonies: await c.get(ceremonies),
			records: await passkeysOf(c),
			challenges: await challengesOf(c),
			verification: c.section["user-verification"],
		}),
	),
	m.provide(registrations).by(async (c) => {
		const holding = await holdingOf(c);
		if (!holding) return c.refuse("passkeys", twoWitnesses);
		return registrationsOver({
			ceremonies: await c.get(ceremonies),
			records: await passkeysOf(c),
			challenges: await challengesOf(c),
			verification: c.section["user-verification"],
			max: c.section["max-credentials"],
			freshHandle: () => freshHandle(c.random.bytes),
			settle: holding.settle,
		});
	}),
	m.provide(passkeyHolders).by(async (c) => {
		const holding = await holdingOf(c);
		if (!holding) return c.refuse("passkeys", twoWitnesses);
		return holding.holders;
	}),
]);
