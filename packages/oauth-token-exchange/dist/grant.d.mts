import type { ClientRepository, GrantDependencies, GrantHandler } from "@o3co/auth-provider-core";
import type { ExchangeTokenValidator } from "./validator/types.mjs";
declare const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
/**
 * Local resolver shape that narrows core's
 * `TokenExchangeValidatorResolver.get(): unknown | undefined` to the
 * concrete `ExchangeTokenValidator` type used internally. Core declares
 * the value as `unknown` to avoid a cross-package import cycle (per
 * contributes-map.mts placeholder pattern). This grant package owns the
 * concrete type, so the narrowed shape is local.
 */
export interface ExchangeTokenValidatorResolver {
    get(tokenType: string): ExchangeTokenValidator | undefined;
}
export interface TokenExchangeDependencies extends GrantDependencies {
    tokenExchangeValidatorResolver: ExchangeTokenValidatorResolver;
    clientRepository: ClientRepository;
}
export declare function createTokenExchangeGrant(deps: TokenExchangeDependencies): GrantHandler;
export { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";
export { GRANT_TYPE as TOKEN_EXCHANGE_GRANT_TYPE };
//# sourceMappingURL=grant.d.mts.map