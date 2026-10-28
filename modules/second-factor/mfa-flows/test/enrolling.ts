import { jsonAnswer } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { factorBinding } from "@mod/mfa-binding";
import { factorManaging } from "@mod/mfa-managing";
import { sessions } from "@mod/session";
import { type EnrollmentFlow, enrollmentFlow, flowParts } from "../src/contract.ts";

/**
 * A plain enrollment for this package's tests, which cannot compose `mfa-enrollment`: a session's
 * binding, or a held login's first one, of a kind that needs no binding proof, counting from the
 * next sign-in. What a binding keeps is `{ pending }`, as the real one keeps it.
 */
export const testEnrollment = defineModule(
	{
		name: "test-enrollment",
		replicaSafe: false,
		takes: [flowParts, factorBinding, factorManaging, sessions],
	},
	(m) => [
		m.contribute(enrollmentFlow).by(async (c): Promise<EnrollmentFlow> => {
			const decided = await c.get(factorBinding);
			const managed = await c.get(factorManaging);
			const open = await c.get(sessions);
			const { transactions, askedFrom, answers, requests } = await c.get(flowParts);
			const pendingOf = (held: unknown) => (held as { pending?: string } | undefined)?.pending;
			return {
				enroll: async (request) => {
					const txId = requests.postedTransaction(request);
					const kind = requests.field(request, "kind") ?? "";
					if (txId) {
						const t = (await transactions.find(request, txId))?.transaction;
						if (t?.purpose !== "enroll-login") return answers.unknownTransaction;
						const begun = await decided.begin(t.subject, kind, undefined, txId, askedFrom(t));
						if (begun.kind !== "begun") return jsonAnswer(400, { error: begun.kind });
						await transactions.keep(txId, () => ({ pending: begun.pending }));
						return jsonAnswer(200, { ...begun.show, transaction: txId });
					}
					const session = await requests.managing(open, request);
					if ("status" in session) return session;
					const from = { kind: "session", handle: session.id } as const;
					const subject = session.context.subject;
					const begun = await decided.begin(subject, kind, undefined, undefined, from);
					if (begun.kind !== "begun") return jsonAnswer(400, { error: begun.kind });
					const held = { pending: begun.pending };
					const kept = await transactions.start({
						subject,
						purpose: "enroll",
						handle: session.id,
						held,
					});
					const at = { transaction: kept.id, expires_in: kept.expiresIn };
					return jsonAnswer(200, { ...begun.show, ...at }, { cookies: kept.cookies });
				},
				complete: async (request) => {
					const txId = requests.postedTransaction(request);
					if (!txId) return answers.unknownTransaction;
					const t = (await transactions.find(request, txId))?.transaction;
					const pending = pendingOf(t?.held);
					if (!t || !pending) return answers.unknownTransaction;
					const left = (await transactions.spend(txId))?.left;
					if (left === undefined) return answers.unknownTransaction;
					const proof = requests.proofOf(request) ?? "";
					const proved = await decided.provePending(t.subject, pending, proof);
					if (proved.kind !== "valid") {
						return jsonAnswer(401, { error: "mfa_invalid", attempts_remaining: left });
					}
					if (!(await transactions.take(txId))) return answers.unknownTransaction;
					const label = requests.field(request, "label");
					const bound = await decided.bind(t.subject, pending, proved.state, label, askedFrom(t));
					if (bound.kind !== "bound") return jsonAnswer(400, { error: bound.kind });
					// The codes are written by the reissue, as the enrollment writes them.
					const reissued = bound.codesDue
						? await managed.reissue(t.subject, bound.fence)
						: undefined;
					const codes = reissued?.kind === "reissued" ? { recovery_codes: reissued.codes } : {};
					const body = { factor: bound.factor, ...codes };
					return jsonAnswer(200, body, { cookies: [transactions.cleared()] });
				},
				challenge: async () => jsonAnswer(200, {}),
			};
		}),
	],
);
