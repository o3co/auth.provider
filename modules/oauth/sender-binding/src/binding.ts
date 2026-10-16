import type { HttpRequest } from "@mod/http";
import type { Binding, BindingOutcome, Scene, SenderBinding } from "./contract.ts";

type Refused = Extract<BindingOutcome, { kind: "refused" }>;

/** A request's binding as the reader finds it; a refusal names the refusing kind's token type. */
export type Reading =
	| Exclude<BindingOutcome, { kind: "refused" }>
	| (Refused & { readonly scheme: string });

/** How two bindings a request proves are settled: an explicit one over ambient ones, or never. */
export type Dispatch = "intent-explicit" | "strict-mutual-exclusion";

export function bindingReader(
	kinds: readonly SenderBinding[],
	issuerUrl: string,
	dispatch: Dispatch,
) {
	return async (request: HttpRequest, scene: Scene): Promise<Reading> => {
		const found: { readonly binding: Binding; readonly explicit: boolean }[] = [];
		for (const kind of kinds) {
			const read = await kind.read(request, scene, issuerUrl);
			if (read.kind === "refused") return { ...read, scheme: kind.tokenType };
			if (read.kind === "bound") {
				const binding = {
					member: kind.member,
					confirmation: read.confirmation,
					tokenType: kind.tokenType,
				};
				found.push({ binding, explicit: kind.explicit === true });
			}
		}
		const explicit = found.filter((f) => f.explicit);
		const contenders = dispatch === "intent-explicit" && explicit.length > 0 ? explicit : found;
		if (contenders.length > 1) return { kind: "multiple_bindings" };
		const [only] = contenders;
		return only ? { kind: "bound", binding: only.binding } : { kind: "none" };
	};
}

/** A reading as `bindingOf` answers it: a refusal without the refusing kind's scheme. */
export function outcomeOf(reading: Reading): BindingOutcome {
	if (reading.kind !== "refused") return reading;
	const { scheme: _, ...refused } = reading;
	return refused;
}
