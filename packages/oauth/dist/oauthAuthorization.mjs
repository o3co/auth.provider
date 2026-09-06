import { createAuthorizationGrant } from "./grants/authorization.mjs";
import { createRefreshTokenGrant } from "./grants/refreshToken.mjs";
export const oauthAuthorizationModule = (params) => ({
    name: "oauth-authorization",
    async init(context) {
        const config = context.config;
        const grantsConfig = config.oauth.grants;
        if (grantsConfig.authorization?.enabled !== false) {
            const handler = createAuthorizationGrant({
                config,
                keyStore: context.keyStore,
                codeRepository: params.codeRepository,
                clientRepository: params.clientRepository,
                refreshTokenStore: context.refreshTokenStore,
                userSessionStore: context.userSessionStore,
                grantPolicy: context.grantPolicy,
            });
            context.grantRegistry.register("authorization", handler);
        }
        if (grantsConfig.refresh_token?.enabled !== false) {
            const handler = createRefreshTokenGrant({
                config,
                keyStore: context.keyStore,
                refreshTokenStore: context.refreshTokenStore,
                userSessionStore: context.userSessionStore,
                grantPolicy: context.grantPolicy,
            });
            context.grantRegistry.register("refresh_token", handler);
        }
    },
});
