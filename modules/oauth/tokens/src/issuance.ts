import { addedClaimsOf } from "@mod/added-claims";
import { deepFreeze, Unavailable } from "@mod/kernel";
import type {
	Admitted,
	IssuancePolicy,
	IssuanceRequest,
	IssuedAccess,
	IssueLimits,
	Tokens,
} from "./contract.ts";
import { actorSnapshot } from "./limits.ts";

/** How far ahead of the clock an authentication time may be, as 0.17 allowed. */
export const authenticatedAheadMs = 300_000;

/** How long the policies may take together unless the section says: its default. */
export const issuanceTimeoutMs = 10_000;

/** What a policy answers, or unavailable once the deadline passes: a policy that never answers holds nothing. */
const within = <T>(answer: Promise<T>, deadline: AbortSignal): Promise<T> => {
	// One answering after the deadline is dropped, its failure included.
	answer.catch(() => {});
	return new Promise<T>((done, failed) => {
		const passed = () => failed(new Unavailable("tokens"));
		if (deadline.aborted) return passed();
		deadline.addEventListener("abort", passed, { once: true });
		answer.then(done, failed).finally(() => deadline.removeEventListener("abort", passed));
	});
};

/**
 * The judgment `admits` and `issue` share: tokens' own rule first, then each policy in name order,
 * all of them within one deadline; past it, unavailable, and each policy's signal aborts.
 */
export function judging(
	policies: readonly IssuancePolicy[],
	now: () => number,
	deadlineOf: () => AbortSignal = () => AbortSignal.timeout(issuanceTimeoutMs),
) {
	const ordered = policies.toSorted((a, b) => (a.name < b.name ? -1 : 1));
	return async (request: IssuanceRequest): Promise<Admitted> => {
		const { authenticatedAt } = request.grant;
		if (authenticatedAt !== undefined && authenticatedAt > now() + authenticatedAheadMs) {
			return {
				kind: "refused",
				policy: "tokens",
				reason: "authenticated_ahead",
				description: "the authentication time is ahead of the clock",
			};
		}
		// The policies read one frozen copy, so none can change what another or the issuing sees.
		const asked = deepFreeze(structuredClone(request));
		const deadline = deadlineOf();
		for (const { name, judge } of ordered) {
			if (deadline.aborted) throw new Unavailable("tokens");
			const verdict = await within(judge(asked, deadline), deadline);
			if (verdict.kind === "allowed") continue;
			// Anything but allowed refuses, so a policy's unreadable answer never issues.
			return verdict.kind === "refused"
				? { ...verdict, policy: name }
				: { kind: "refused", policy: name, reason: "unreadable", description: "issuance refused" };
		}
		return { kind: "allowed" };
	};
}

/** The issuing `issue` does once the judgment allows it, without asking the policies itself. */
export type IssueAccess = (
	grant: IssuanceRequest["grant"],
	limits?: IssueLimits,
) => Promise<IssuedAccess>;

/**
 * The request with the claims its grant adds checked and copied, before anything else reads them;
 * an empty set is none. Throws TypeError, the grant's maker's mistake, on claims outside the rules
 * or an actor chain deeper than tokens reads, counted before anything copies it.
 */
function checkedRequest(request: IssuanceRequest): IssuanceRequest {
	// Each of the caller's properties is read once: what is checked is what is copied and signed.
	const { grant: given, ...rest } = request;
	const { claims: added, actor: chain, ...grant } = given;
	const actor = actorSnapshot(chain);
	const claims = addedClaimsOf(added);
	return {
		...rest,
		grant: { ...grant, ...(actor ? { actor } : {}), ...(claims ? { claims } : {}) },
	};
}

/**
 * `admits` and `issue` over the judgment and the issuing, alike for tokens and its stand-in. A
 * token's lifetime is answered from when its issuing is done, its signing included.
 */
export function issuing(
	judge: (request: IssuanceRequest) => Promise<Admitted>,
	issueAccess: IssueAccess,
	now: () => number,
): Pick<Tokens, "admits" | "issue"> {
	return {
		admits: async (request) => judge(checkedRequest(request)),
		issue: async (request, limits) => {
			// One frozen copy, taken before anything waits, is both what the policies judge and what is
			// signed: a caller changing its own grant or limits meanwhile changes neither.
			const taken = deepFreeze(structuredClone({ request: checkedRequest(request), limits }));
			const judged = await judge(taken.request);
			if (judged.kind === "refused") return judged;
			const access = await issueAccess(taken.request.grant, taken.limits);
			// What is left once signed, rounded up, so a token signed at once answers its whole lifetime;
			// none where its end has come, its cap passed or its signing slow.
			const leftMs = access.expiresAt - now();
			return {
				kind: "issued",
				access: { ...access, expiresIn: Math.max(0, Math.ceil(leftMs / 1000)) },
			};
		},
	};
}
