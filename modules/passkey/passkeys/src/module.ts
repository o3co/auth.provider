import { type BuildContext, defineModule } from "@mod/kernel";
import { ceremonies, freshHandle } from "@mod/webauthn";
import { challengeStore, passkeyStore, passkeys, registrations } from "./contract.ts";
import { passkeysOver } from "./passkeys.ts";
import { keptChallenges, keptPasskeys } from "./records.ts";
import { registrationsOver } from "./registration/registrations.ts";
import { type Settings, section } from "./section.ts";

type Context = BuildContext<Settings>;
const passkeysOf = async (c: Context) => keptPasskeys(await c.get(passkeyStore), c.clock.now);
// A challenge lives as long as the relying party lets one be answered.
const challengesOf = async (c: Context) =>
	keptChallenges(await c.get(challengeStore), c.clock.now, (await c.get(ceremonies)).lifetimeMs);

export default defineModule({ name: "passkeys", section, replicaSafe: true }, (m) => [
	m.provide(passkeys).by(async (c) =>
		passkeysOver({
			ceremonies: await c.get(ceremonies),
			records: await passkeysOf(c),
			challenges: await challengesOf(c),
			verification: c.section["user-verification"],
		}),
	),
	m.provide(registrations).by(async (c) =>
		registrationsOver({
			ceremonies: await c.get(ceremonies),
			records: await passkeysOf(c),
			challenges: await challengesOf(c),
			verification: c.section["user-verification"],
			max: c.section["max-credentials"],
			freshHandle: () => freshHandle(c.random.bytes),
		}),
	),
]);
