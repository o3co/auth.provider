import type { Client } from "@mod/clients";
import { contract, extensionPoint } from "@mod/kernel";

/** A value a constraint names: claims-selection keeps it as it is, never reading what it means. */
export type Scalar = string | boolean | number;

/** A claim the request names, with the one value or the values it must hold to be released. */
export interface Constraint {
	readonly name: string;
	readonly value?: Scalar;
	readonly values?: readonly Scalar[];
}

/** A claim the request names, and the scope it belongs to. */
export interface Named {
	readonly name: string;
	readonly scope: string;
}

/** What one target (the ID token, or userinfo) releases beyond its scope, and the constraints on all it releases. */
export interface Target {
	readonly names: readonly Named[];
	readonly constraints: readonly Constraint[];
}

export interface Selection {
	readonly idToken: Target;
	readonly userinfo: Target;
}

/** The bounds a selection keeps within: longer strings, more values or a larger whole are refused. */
export const selectionLimits = { valueLength: 256, values: 16, bytes: 4096 } as const;

/** An access token as a selection is kept for it. */
export interface Issued {
	readonly id: string;
	/** Epoch ms. */
	readonly expiresAt: number;
}

/**
 * Whether selections are taken: `off` takes none and touches no store; `draining` keeps holding back
 * what was kept but keeps nothing new; `on` takes them.
 */
export type SelectionMode = "off" | "draining" | "on";

export interface ClaimsSelections {
	readonly mode: SelectionMode;
	/** The names the client is allowed and the subject agreed to, by their scopes; the constraints as they are. */
	select(client: Client, subject: string, asked: Selection): Promise<Selection>;
	/** Keeps a code's selection by its redemption's name, for the code's lifetime and a minute more; only while `on`. */
	keepForCode(redemption: string, selection: Selection, lifetimeMs: number): Promise<void>;
	/** The selection pinned to a redemption: none for a code without one; throws once the pin is gone. */
	forCode(redemption: string): Promise<Selection | undefined>;
	/** The userinfo target kept for an access token; none for a token without one. */
	forToken(tokenId: string): Promise<Target | undefined>;
	/** Keeps the userinfo target pinned to a redemption for the family founded from it. */
	follow(redemption: string, familyId: string, lifetimeMs: number): Promise<void>;
	/** Keeps for a refreshed token its family's target, the names cut to what is allowed and agreed to now. */
	forRefreshed(familyId: string, client: Client, subject: string, access: Issued): Promise<void>;
}

export const claimsSelections = contract<ClaimsSelections>("claims-selection");

/** Whether the subject agreed to the client for a scope, as the module asking for consent judges it. */
export interface SelectionConsent {
	consented(client: Client, subject: string, scope: string): Promise<boolean>;
}

export const selectionConsents = extensionPoint<SelectionConsent>("claims-selection.consents", {
	multiplicity: "many",
});

export * from "./store.ts";
