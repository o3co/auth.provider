import { redirects } from "@mod/redirect-uris";

/** What authorize contributes to `clients`: the section of the redirect URIs its requests are checked against. */
export const clientMetadata = { section: redirects } as const;
