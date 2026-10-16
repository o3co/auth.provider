import type {
	Admitted,
	IssuancePolicy,
	IssuanceRequest,
	IssuedAccess,
	IssueLimits,
	Tokens,
} from "./contract.ts";

/** How far ahead of the clock an authentication time may be, as 0.17 allowed. */
export const authenticatedAheadMs = 300_000;

/** The judgment `admits` and `issue` share: tokens' own rule first, then each policy in name order. */
export function judging(policies: readonly IssuancePolicy[], now: () => number) {
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
		for (const { name, judge } of ordered) {
			const verdict = await judge(request);
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

/** `admits` and `issue` over the judgment and the issuing, alike for tokens and its stand-in. */
export function issuing(
	judge: (request: IssuanceRequest) => Promise<Admitted>,
	issueAccess: IssueAccess,
): Pick<Tokens, "admits" | "issue"> {
	return {
		admits: judge,
		issue: async (request, limits) => {
			const judged = await judge(request);
			if (judged.kind === "refused") return judged;
			return { kind: "issued", access: await issueAccess(request.grant, limits) };
		},
	};
}
