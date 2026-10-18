import { type BuildContext, defineModule } from "@mod/kernel";
import { mail, mailPurposes } from "@mod/mail";
import { factorKinds } from "@mod/mfa";
import { bindingProof, bindingProofs } from "@mod/mfa-binding-proof";
import { subjectAttributes } from "@mod/subject-attributes";
import { users } from "@mod/users";
import { purposes } from "./contract.ts";
import { emailFactor } from "./kind.ts";
import { type Settings, section } from "./section.ts";

export default defineModule({ name: "mfa-email", section, replicaSafe: true }, (m) => {
	// Stateless: each contribution builds its own.
	const build = async (c: BuildContext<Settings>) =>
		emailFactor({
			mail: await c.get(mail),
			users: await c.get(users),
			// Late: session's own build asks mfa, which asks this kind.
			attributes: c.late(subjectAttributes),
			addsSecondFactor: c.section["adds-second-factor"],
			codeMs: c.section["code-lifetime"] * 1000,
			now: c.clock.now,
			random: c.random.bytes,
		});
	return [
		m.contribute(factorKinds).by(async (c) => (await build(c)).kind),
		m.contribute(bindingProofs).by(async (c) => {
			// Named late, as it collects this proof: boot refuses where it is not composed to hear it.
			c.late(bindingProof);
			return (await build(c)).proof;
		}),
		...Object.values(purposes).map((purpose) => m.contribute(mailPurposes).by(() => ({ purpose }))),
	];
});
