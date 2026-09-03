/**
 * Public exports for `@o3co/auth-provider-device-grant` (RFC 8628, #298).
 *
 * Deliberately NOT exported: the `DeviceCodeStore` port and the code
 * generators live in `@o3co/auth-provider-core`, so an adapter author depends
 * on core alone and never on this package. That is what lets
 * `@o3co/auth-provider-redis` ship a device-code store without taking a
 * dependency on the grant that consumes it.
 */
export { createDeviceAuthorizationHandler, type DeviceAuthorizationEndpointOptions, } from "./deviceAuthorizationEndpoint.mjs";
export { createDeviceCodeGrant, type DeviceCodeGrantOptions } from "./grant.mjs";
export { deviceGrantConfigSchema, deviceGrantModule } from "./module.mjs";
export { DEVICE_AUTHORIZATION_RATE_LIMIT_PREFIX, DEVICE_CODE_GRANT_TYPE, DEVICE_VERIFICATION_RATE_LIMIT_PREFIX, type DeviceAuthorizationSettings, type DeviceGrantDependencies, } from "./types.mjs";
export { createDeviceVerificationHandler, type DeviceVerificationHandlerOptions, } from "./verificationEndpoint.mjs";
//# sourceMappingURL=index.d.mts.map