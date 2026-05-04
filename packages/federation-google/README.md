# @o3co/auth-provider-federation-google

Google federation provider for `auth.provider`.

## Usage

Add `googleFederationModule` to the manifest list passed to `createApp`. A small
config-bootstrap module supplies the typed `googleFederationConfig` slot (per
A5 §10.1 const-Module pattern).

```ts
import { createApp, defineModule } from "@o3co/auth-provider-core";
import { extractFederationSection, sessionModule } from "@o3co/auth-provider-session";
import {
  googleFederationModule,
  type GoogleProviderConfig,
} from "@o3co/auth-provider-federation-google";

const googleConfigBridgeModule = defineModule({
  name: "google-federation-config",
  requires: ["config"] as const,
  provides: {
    googleFederationConfig: (deps): GoogleProviderConfig => {
      const slice = extractFederationSection(deps.config.federations, "google");
      if (!slice) throw new Error("federations.google must be enabled");
      return {
        clientId: slice.clientId as string,
        clientSecret: slice.clientSecret as string,
        callbackURL: slice.callbackURL as string,
      };
    },
  },
});

const handle = await createApp({
  modules: [
    sessionModule,
    googleFederationModule,
    googleConfigBridgeModule,
    // ... composition-root modules supplying userRepository + four-store split
  ],
  bootstrapComponents: { config, pathResolver },
});
```

v0.5.0 is single-tenant: `provider.name` is fixed at `"google"`. Multi-tenant
setups (multiple Google apps in one provider) are deferred post-publish.

## Public API

- `googleFederationModule` — const Module contributing `federations.google` +
  `federationRedirectPolicies.google`
- `createGoogleProvider(config: GoogleProviderConfig): GoogleProvider` —
  pure constructor
- `GoogleProviderConfig`, `GoogleProvider` — types
- `googleFederationConfig` — declared ComponentMap slot for the config bridge
