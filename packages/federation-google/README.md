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

### The callback's `iss` (RFC 9207)

Google's discovery document advertises
`authorization_response_iss_parameter_supported`, and its OpenID Connect
reference says of the authorization response's `iss`: "Per RFC 9207, this
parameter is always returned and set to `https://accounts.google.com`". So this
provider compares the callback's `iss` with Google's issuer, as an exact
string, and **refuses a callback that carries none**. Both refusals happen
before the code is spent at the token endpoint.

The server metadata here is written by hand, not discovered, so a deployment
could not otherwise react if Google ever stopped sending the parameter.
`requireAuthorizationResponseIss: false` in `GoogleProviderConfig` is the way
out: it permits a missing `iss` and nothing else. One that is sent and is not
Google's is refused either way. The bridge above forwards three fields; forward
this one too if the deployment should be able to set it, as the standalone
template's bridge does. **It must be a boolean.** An environment override
arrives as the string `"false"`, which is truthy, so `createGoogleProvider`
refuses anything that is not a boolean instead of quietly keeping the
requirement on; coerce the string in the bridge.

If every Google login starts answering `502 exchange_failed` with the log cause
`response parameter "iss" (issuer) missing`, either Google stopped sending the
parameter or something between Google and this server drops it: a gateway with
a query-parameter allowlist, or a front end that relays only `code` and
`state` to `callbackURL`. Let `iss` through; the switch above is the stopgap.

v0.5.0 is single-tenant: `provider.name` is fixed at `"google"`. Multi-tenant
setups (multiple Google apps in one provider) are deferred post-publish.

## Public API

- `googleFederationModule` — const Module contributing `federations.google` +
  `federationRedirectPolicies.google`
- `createGoogleProvider(config: GoogleProviderConfig): GoogleProvider` —
  pure constructor
- `GoogleProviderConfig`, `GoogleProvider` — types
- `googleFederationConfig` — declared ComponentMap slot for the config bridge
