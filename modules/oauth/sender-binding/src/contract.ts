import type { Client } from "@mod/clients";
import type { HttpRequest } from "@mod/http";
import { contract, extensionPoint } from "@mod/kernel";

/** Where a binding is read: at issuance, or at a resource presenting the token. */
export type Scene =
	| { readonly kind: "issue" }
	| { readonly kind: "resource"; readonly token: string };

/** What one binding kind reads from a request. */
export type BindingRead =
	| { readonly kind: "absent" }
	| { readonly kind: "bound"; readonly confirmation: string }
	| {
			readonly kind: "refused";
			/** The contributing side's spec code, passed through unread. */
			readonly error: string;
			readonly description?: string;
			readonly unavailable?: boolean;
			readonly headers?: Readonly<Record<string, string>>;
	  };

/** A binding kind: the `cnf` member it writes, the token type it makes, and how it reads a request. */
export interface SenderBinding {
	readonly member: string;
	readonly tokenType: string;
	/** A proof the client sends on purpose, such as DPoP's, rather than an ambient one such as a certificate. */
	readonly explicit?: boolean;
	/** The name operators give it in a client's requirement, such as `dpop`; without one, no client can name it. */
	readonly name?: string;
	read(request: HttpRequest, scene: Scene, issuer: string): Promise<BindingRead>;
}

/** A binding a request proved, as a token carries it. */
export interface Binding {
	readonly member: string;
	readonly confirmation: string;
	readonly tokenType: string;
}

export type BindingOutcome =
	| { readonly kind: "none" }
	| { readonly kind: "bound"; readonly binding: Binding }
	| { readonly kind: "multiple_bindings" }
	| Extract<BindingRead, { kind: "refused" }>;

/** A token's validity as its issuer reads it; a valid bound one names its binding. */
export type TokenCheck =
	| {
			readonly kind: "valid";
			readonly binding?: Binding;
	  }
	| { readonly kind: "invalid" };

/** The issuer's check of a token's validity (signature, expiry, revocation); throws Unavailable when it cannot tell. */
export interface TokenValidity<C extends TokenCheck> {
	verifyAccess(token: string): Promise<C>;
}

/** A resource's answer to a request presenting a token; a refusal carries `WWW-Authenticate`. */
export type Admission<C extends TokenCheck> =
	| { readonly kind: "admitted"; readonly access: Extract<C, { kind: "valid" }> }
	| {
			readonly kind: "refused";
			readonly status: 400 | 401;
			/** None when the request presented no token. */
			readonly error?: string;
			readonly headers: Readonly<Record<string, string>>;
	  };

export interface SenderBindings {
	/** The binding a request proves, read by every kind; two or more answer `multiple_bindings`. */
	bindingOf(request: HttpRequest, scene: Scene): Promise<BindingOutcome>;
	/** The token type of the kind that writes this `cnf` member; none for a member no kind writes. */
	tokenTypeOf(member: string): string | undefined;
	/**
	 * Admits a request at a resource: the scheme matches the token's type, the token is valid, and
	 * a bound token's holder proves its binding. Throws Unavailable when a check cannot tell.
	 */
	admitted<C extends TokenCheck>(
		request: HttpRequest,
		tokens: TokenValidity<C>,
	): Promise<Admission<C>>;
}

export const senderBinding = contract<SenderBindings>("sender-binding");

export const senderBindings = extensionPoint<SenderBinding>("sender-binding.kinds", {
	multiplicity: "keyed",
	keyOf: (binding) => binding.member,
});

/** The same kind and the same key, or both absent. */
export function sameBinding(a: Binding | undefined, b: Binding | undefined): boolean {
	return a?.member === b?.member && a?.confirmation === b?.confirmation;
}

/** Whether the token issued for presented tokens keeps their binding, and the binding it gets. */
export type Carried =
	| { readonly kind: "carry"; readonly binding?: Binding }
	| { readonly kind: "refused" };

/**
 * Carries the bindings of the tokens a request presents (`held`, absent for an unbound token) to
 * the token issued for them. Each held binding must be the one the request proved; the new token
 * is bound to what the request proved, if anything.
 */
export function carried(
	held: readonly (Binding | undefined)[],
	proved: Binding | undefined,
): Carried {
	// A binding the request does not prove would be washed off; two different ones never both match.
	if (held.some((binding) => binding && !sameBinding(binding, proved))) return { kind: "refused" };
	return proved ? { kind: "carry", binding: proved } : { kind: "carry" };
}

/** A resource's challenge for a token it refuses itself, in the token's type (RFC 6750 §3). */
export function challengeOf(
	tokenType: string,
	error: string,
): { readonly "www-authenticate": string } {
	return { "www-authenticate": `${tokenType} error="${error}"` };
}

export interface ClientBindings {
	/** Why a binding read at issuance does not do for the client's `sender-binding` section: none though one is required, or a kind it does not name. */
	refusalOf(client: Client, binding: Binding | undefined): "required" | "kind" | undefined;
}

export const clientBindings = contract<ClientBindings>("sender-binding.client-bindings");
