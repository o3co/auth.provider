import type { RequestHandler } from "express";
import { type DeviceGrantDependencies } from "./types.mjs";
export interface DeviceAuthorizationEndpointOptions extends DeviceGrantDependencies {
}
export declare const createDeviceAuthorizationHandler: (options: DeviceAuthorizationEndpointOptions) => RequestHandler;
//# sourceMappingURL=deviceAuthorizationEndpoint.d.mts.map