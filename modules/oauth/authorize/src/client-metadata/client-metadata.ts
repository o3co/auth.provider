import { redirects, redirectsCopy } from "@mod/redirect-uris";

/**
 * What authorize contributes for clients: the section of the redirect URIs its requests are checked
 * against, and that section's copy from a client's metadata document.
 */
export const clientMetadata = { section: redirects, copy: redirectsCopy } as const;
