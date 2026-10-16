import { type BuildContext, defineModule } from "@mod/kernel";
import { ceremoniesFor } from "./ceremony/ceremony.ts";
import { ceremonies, challengeStore, passkeyStore, passkeys, registrations } from "./contract.ts";
import { passkeysOver } from "./passkeys.ts";
import { freshHandle, keptChallenges, keptPasskeys } from "./records.ts";
import { registrationsOver } from "./registration/registrations.ts";
import { type Settings, section } from "./section.ts";

const relyingParty = (s: Settings) => ({
	id: s["rp-id"],
	name: s["rp-name"],
	origins: s.origins,
	topOrigins: s["top-origins"],
	timeoutMs: s["challenge-seconds"] * 1000,
});

type Context = BuildContext<Settings>;
const passkeysOf = async (c: Context) => keptPasskeys(await c.get(passkeyStore));
const challengesOf = async (c: Context) =>
	keptChallenges(await c.get(challengeStore), c.clock.now, c.section["challenge-seconds"] * 1000);

export default defineModule({ name: "webauthn", section, replicaSafe: true }, (m) => [
	m
		.provide(ceremonies)
		.by((c) => ceremoniesFor(relyingParty(c.section), c.random.bytes, c.clock.now)),
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
