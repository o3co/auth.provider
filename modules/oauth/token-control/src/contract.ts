import type { Client } from "@mod/clients";
import { extensionPoint } from "@mod/kernel";

/** "written": this call wrote the revocation; "done": nothing left to do, as for another client's token. */
export type Revoked = "done" | "unknown" | "unsupported" | "written";

export interface RevocableKind {
	readonly hint: string;
	revoke(token: string, client: Client): Promise<Revoked>;
}

export const revocableKinds = extensionPoint<RevocableKind>("token-control.revocable-kinds", {
	multiplicity: "keyed",
	keyOf: (kind) => kind.hint,
});
