import { type BuildContext, defineModule, Unavailable } from "@mod/kernel";
import { type AskedFrom, firstBindingGates } from "@mod/mfa-extensions";
import { factorReading } from "@mod/mfa-reading";
import { type Seal, seal } from "@mod/seal";
import { z } from "zod";
import { type BindingProof, bindingProof, bindingProofs, type PassBound } from "./contract.ts";

const section = z.strictObject({
	mode: z
		.enum(["never", "when-available", "always"])
		.prefault("when-available")
		.describe(
			"Whether a first counting factor waits for a binding proof: never, when one is available, or always.",
		),
});

type Context = BuildContext<z.output<typeof section>>;

/** What a sent challenge keeps, sealed to the subject: the proof's name, what it kept, and its end. */
interface SentChallenge {
	readonly proof: string;
	readonly kept: string;
	readonly until: number;
}
/** What a proved challenge gives, sealed to the subject: its end, and the binding it begins. */
type Pass = PassBound & { readonly until: number };

const challengeContext = (subject: string) => `${subject}\nmfa-binding-proof challenge`;
const passContext = (subject: string) => `${subject}\nmfa-binding-proof pass`;

/** The proof asked of a subject, if any, and the sealing of its challenge and pass; holding a factor is mfa's to tell. */
async function provingIn(c: Context) {
	const proofs = await c.collect(bindingProofs);
	const sealing: Seal = await c.get(seal);
	const { mode } = c.section;
	/** Sealed values come back only from mfa-flows' transactions: one that will not open is a fault. */
	const opened = <T>(sealed: string, context: string): T => {
		const plain = sealing.open(sealed, context);
		if (plain.kind !== "opened") throw new Unavailable("mfa-binding-proof");
		return JSON.parse(plain.plain) as T;
	};
	const inTime = (until: number) => c.clock.now() <= until;
	/** The proof a subject is asked, whatever it holds: under `always`, the first contributed, which the contract's build refuses to boot without. */
	const proofFor = async (subject: string, from?: AskedFrom): Promise<BindingProof | undefined> => {
		if (mode === "never") return undefined;
		for (const proof of proofs) if (await proof.available(subject, from)) return proof;
		return mode === "always" ? proofs[0] : undefined;
	};
	return { proofs, mode, sealing, opened, inTime, proofFor };
}

export default defineModule(
	{
		name: "mfa-binding-proof",
		// Safe on many instances given the same seal key and clocks in step on each (deployment-guarantees, Several
		// instances).
		replicaSafe: true,
		section,
		takes: [bindingProofs, factorReading, seal],
	},
	(m) => [
		m.provide(bindingProof).by(async (c) => {
			const p = await provingIn(c);
			// The operator's choice, yet said at every start: a first factor binds with nothing proved.
			if (p.mode === "never") {
				c.log.warn("mfa-binding-proof.never_asked", {
					reason: "a first counting factor binds with no binding proof asked",
				});
			}
			if (p.mode === "always" && p.proofs.length === 0) {
				return c.refuse(
					"mfa-binding-proof.proofs",
					"mode is always, but no binding proof is composed",
				);
			}
			const mfa = await c.get(factorReading);
			/** The proof asked of a subject that holds no counting factor yet. */
			const asked = async (subject: string, from?: AskedFrom) =>
				(await mfa.countingHeld(subject, "binding")) ? undefined : p.proofFor(subject, from);
			return {
				asks: async (subject, from) => ((await asked(subject, from)) ? "proof" : "nothing"),
				challenge: async (subject, until, from) => {
					const proof = await asked(subject, from);
					if (!proof) return { kind: "none" };
					const sending = await proof.send(subject, until, from);
					if (sending.kind === "limited") return sending;
					if (sending.kind === "refused") return { kind: "refused", proof: proof.name };
					const kept: SentChallenge = { proof: proof.name, kept: sending.kept, until };
					const sealed = p.sealing.seal(JSON.stringify(kept), challengeContext(subject));
					return { kind: "sent", proof: proof.name, show: sending.show, sealed };
				},
				prove: async (subject, answer, challenge, bound) => {
					const sent = p.opened<SentChallenge>(challenge, challengeContext(subject));
					const proof = p.proofs.find((candidate) => candidate.name === sent.proof);
					if (!proof || !p.inTime(sent.until)) return undefined;
					if (!(await proof.check(subject, sent.kept, answer))) return undefined;
					const pass: Pass = {
						until: sent.until,
						transaction: bound.transaction,
						kind: bound.kind,
					};
					return p.sealing.seal(JSON.stringify(pass), passContext(subject));
				},
			};
		}),
		// mfa asks a gate only while the subject holds no counting factor; getting `factorReading` here would
		// cycle, as mfa collects this gate while it builds them.
		m.contribute(firstBindingGates).by(async (c) => {
			const p = await provingIn(c);
			return {
				admits: async ({ subject, kind, transaction, passed, from }) => {
					if (!(await p.proofFor(subject, from))) return true;
					if (passed === undefined) return false;
					const pass = p.opened<Pass>(passed, passContext(subject));
					return p.inTime(pass.until) && pass.transaction === transaction && pass.kind === kind;
				},
			};
		}),
	],
);
