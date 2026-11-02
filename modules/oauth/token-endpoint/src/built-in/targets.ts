import { type TargetRule, targetRules } from "@mod/grants";
import type { BuildContext } from "@mod/kernel";

export const unread: TargetRule = { target: ({ audience }) => ({ kind: "audience", audience }) };

/** What `composedRule` takes from the build context. */
export const targetTakes = [targetRules] as const;

export async function composedRule(c: Pick<BuildContext<unknown>, "collect" | "refuse">) {
	const rules = await c.collect(targetRules);
	if (rules.length > 1) {
		return c.refuse("token-endpoint.target-rules", "at most one rule for a request's audience");
	}
	return rules[0] ?? unread;
}
