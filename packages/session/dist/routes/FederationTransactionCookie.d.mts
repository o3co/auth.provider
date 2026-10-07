/**
 * Where a `form_post` federation keeps its transaction: the record's store,
 * taken off the request, and the cookie that addresses it — one per
 * federation, `__Host-`, `HttpOnly`, `Secure`, `SameSite=None`, `Path=/`.
 */
import type { FederationProvider } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { type FederationTransactionStore } from "../federations/transaction.mjs";
/**
 * Attributes shared by the `Set-Cookie` that issues the cookie and the one
 * that clears it. `Path=/` and no `Domain`, as the `__Host-` name requires.
 */
declare const transactionCookieAttributes: {
    readonly httpOnly: true;
    readonly secure: true;
    readonly sameSite: "none";
    readonly path: "/";
};
/** The transaction's store and cookie, as the start writes them and the callback reads and clears them. */
export interface FederationTransactionCookie {
    /** The cookie that carries `provider`'s transaction id. */
    readonly transactionCookieName: (provider: FederationProvider) => string;
    readonly transactionStore: (req: Request) => FederationTransactionStore | undefined;
    readonly transactionCookieAttributes: typeof transactionCookieAttributes;
    readonly clearTransactionCookie: (provider: FederationProvider, res: Response) => void;
}
/** The transaction cookies, each federation's named from `sessionCookieName`. */
export declare const createTransactionCookie: (sessionCookieName: string) => FederationTransactionCookie;
export {};
//# sourceMappingURL=FederationTransactionCookie.d.mts.map