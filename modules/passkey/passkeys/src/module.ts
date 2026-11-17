import { erasers } from "@mod/erasure-extensions";
import { type BuildContext, contract, defineModule, optional } from "@mod/kernel";
import { passkeyWitnesses } from "@mod/passkey-witness";
import { ceremonies, freshHandle } from "@mod/webauthn";
import { type KeptChallenges, keptChallenges } from "./challenges/challenges.ts";
import {
	challengeStore,
	type PasskeyHolders,
	passkeyClearing,
	passkeyHolders,
	passkeyHolding,
	passkeyReading,
	passkeyStore,
	passkeys,
	passkeyWitnessing,
	registrationChallengeStore,
	registrations,
} from "./contract.ts";
import { passkeysEraser } from "./erasure/eraser.ts";
import { holdersOver } from "./holders/holders.ts";
import { passkeysOver } from "./passkeys.ts";
import { portsRefused, registrationPortsRefused } from "./ports/ports.ts";
import { type KeptPasskeys, keptPasskeys } from "./records.ts";
import { registrationsOver } from "./registration/registrations.ts";
import { type Settings, section } from "./section.ts";

type Context = BuildContext<Settings>;
/** A new token: 16 random bytes, unpadded base64url. */
const tokenOf = (c: Context) => () => Buffer.from(c.random.bytes(16)).toString("base64url");
/** The passkey records, made once for the module's parts. */
const kept = contract<KeptPasskeys>("passkeys.records");
const passkeysOf = (c: Context) => c.get(kept);
/** The holders, made once for each face of holding. */
const made = contract<PasskeyHolders>("passkeys.holders-made");
/** The challenges, made once for the module's parts. */
const challengesKept = contract<KeptChallenges>("passkeys.challenges");
const challengesOf = (c: Context) => c.get(challengesKept);
/** The holdings over the one witnessing contributed, if any; two, or a witness with none, refuse boot. */
const holdingOf = async (c: Context) => {
	const [witnessing, ...others] = await c.collect(passkeyWitnessing);
	const witnesses = await c.collect(passkeyWitnesses);
	if (others.length > 0) {
		return { refused: "more than one passkey witnessing is contributed" } as const;
	}
	// A witness nothing asks would leave a lost store to read as holding none: never silently.
	if (!witnessing && witnesses.length > 0) {
		return { refused: "a passkey witness is composed without passkey-witnessing" } as const;
	}
	const holding = holdersOver({
		records: await passkeysOf(c),
		witnessing,
		handle: () => freshHandle(c.random.bytes),
	});
	return { holding } as const;
};

export default defineModule(
	{
		name: "passkeys",
		section,
		replicaSafe: true,
		takes: [
			challengeStore,
			// TODO(0.22): required.
			optional(registrationChallengeStore),
			passkeyStore,
			passkeyWitnesses,
			passkeyWitnessing,
			ceremonies,
		],
	},
	(m) => [
		// Over a passkey store, its ports whole: checked here, as the types cannot say all or none.
		// A challenge lives as long as the relying party lets one be answered; over a registration
		// challenge store, where composed, its ports whole.
		m.provide(challengesKept).by(async (c) => {
			const registrations = await c.getOptional(registrationChallengeStore);
			const parted = registrations && registrationPortsRefused(registrations);
			if (parted !== undefined) return c.refuse("passkeys", parted);
			return keptChallenges(
				await c.get(challengeStore),
				c.clock.now,
				(await c.get(ceremonies)).lifetimeMs,
				registrations,
			);
		}),
		m.provide(kept).by(async (c) => {
			const store = await c.get(passkeyStore);
			const parted = portsRefused(store);
			if (parted !== undefined) return c.refuse("passkeys", parted);
			return keptPasskeys(store, tokenOf(c), c.clock.now);
		}),
		m.provide(passkeys).by(async (c) => {
			// The operator's choice, yet said at every start: whoever holds the authenticator passes.
			if (c.section["user-verification"] === "discouraged") {
				c.log.warn("passkeys.user_unverified", {
					reason: "the authenticator is not asked to verify its user",
				});
			}
			return passkeysOver({
				ceremonies: await c.get(ceremonies),
				records: await passkeysOf(c),
				challenges: await challengesOf(c),
				verification: c.section["user-verification"],
			});
		}),
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
		m.provide(passkeyReading).by(async (c) => {
			const records = await passkeysOf(c);
			return { writtenHolding: (subject) => records.writtenHolding(subject) };
		}),
		// Its build takes only the stores, collecting no probes: the erasure gate collects erasers.
		m
			.contribute(erasers)
			.by(async (c) =>
				passkeysEraser(await c.get(passkeyStore), await c.getOptional(registrationChallengeStore)),
			),
		m.provide(made).by(async (c) => {
			const held = await holdingOf(c);
			if ("refused" in held) return c.refuse("passkeys", held.refused);
			return held.holding.holders;
		}),
		m.provide(passkeyHolders).by((c) => c.get(made)),
		m.provide(passkeyHolding).by(async (c) => {
			const { held, witnessed } = await c.get(made);
			return { held, witnessed };
		}),
		m.provide(passkeyClearing).by(async (c) => {
			const { cleared, settle } = await c.get(made);
			return { cleared, settle };
		}),
	],
);
