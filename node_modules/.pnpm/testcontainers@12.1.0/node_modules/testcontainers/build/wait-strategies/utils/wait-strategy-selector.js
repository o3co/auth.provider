"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.selectWaitStrategy = void 0;
const common_1 = require("../../common");
const container_runtime_1 = require("../../container-runtime");
const wait_1 = require("../wait");
const health_check_1 = require("./health-check");
const selectWaitStrategy = async ({ client, inspectResult, waitStrategy, healthCheck, imageNames = getImageNames(inspectResult), }) => {
    if (waitStrategy)
        return waitStrategy;
    if ((0, health_check_1.hasHealthCheck)(healthCheck))
        return wait_1.Wait.forHealthCheck();
    if ((0, health_check_1.hasDisabledHealthCheckConfig)(inspectResult))
        return wait_1.Wait.forListeningPorts();
    if ((0, health_check_1.hasHealthCheckConfig)(inspectResult) || (0, health_check_1.hasHealthCheckStatus)(inspectResult))
        return wait_1.Wait.forHealthCheck();
    if (await imageHasHealthCheck(client, imageNames))
        return wait_1.Wait.forHealthCheck();
    return wait_1.Wait.forListeningPorts();
};
exports.selectWaitStrategy = selectWaitStrategy;
const getImageNames = (inspectResult) => {
    return Array.from(new Set([inspectResult.Config.Image, inspectResult.Image].filter((imageName) => imageName !== undefined && imageName !== "")));
};
const imageHasHealthCheck = async (client, imageNames) => {
    for (const imageName of imageNames) {
        try {
            if ((0, health_check_1.hasHealthCheckConfig)(await client.image.inspect(container_runtime_1.ImageName.fromString(imageName)))) {
                return true;
            }
        }
        catch (err) {
            common_1.log.warn(`Failed to inspect image "${imageName}" for health check config: ${err}`);
        }
    }
    return false;
};
