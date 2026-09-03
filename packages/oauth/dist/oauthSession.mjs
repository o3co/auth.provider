import { createSessionGrant } from "./grants/session.mjs";
export const oauthSessionModule = (params) => ({
    name: "oauth-session",
    async init(context) {
        const config = context.config;
        const grantConfig = config.oauth.grants.session;
        if (grantConfig?.enabled === false)
            return;
        const handler = createSessionGrant({
            config,
            keyStore: context.keyStore,
            clientRepository: params.clientRepository,
        });
        context.grantRegistry.register("session", handler);
    },
});
