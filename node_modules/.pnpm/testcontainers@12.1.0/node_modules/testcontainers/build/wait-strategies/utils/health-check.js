"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hasHealthCheckStatus = exports.getHealthCheckStatusFromInspect = exports.hasDisabledHealthCheckConfig = exports.hasHealthCheckConfig = exports.getHealthCheckConfig = exports.hasHealthCheck = exports.isHealthCheckDisabled = void 0;
const DISABLED_HEALTH_CHECK_TEST = "NONE";
const getHealthCheckTest = (healthCheck) => {
    if ("test" in healthCheck) {
        return healthCheck.test;
    }
    return healthCheck.Test;
};
const isDisabledHealthCheck = (test) => {
    return test[0].toUpperCase() === DISABLED_HEALTH_CHECK_TEST;
};
const isHealthCheckDisabled = (healthCheck) => {
    if (healthCheck === undefined) {
        return false;
    }
    const test = getHealthCheckTest(healthCheck);
    if (test === undefined || test.length === 0) {
        return false;
    }
    return isDisabledHealthCheck(test);
};
exports.isHealthCheckDisabled = isHealthCheckDisabled;
const hasHealthCheck = (healthCheck) => {
    if (healthCheck === undefined) {
        return false;
    }
    const test = getHealthCheckTest(healthCheck);
    if (test === undefined || test.length === 0) {
        return false;
    }
    return !(0, exports.isHealthCheckDisabled)(healthCheck);
};
exports.hasHealthCheck = hasHealthCheck;
const getHealthCheckConfig = (inspectResult) => {
    const inspectWithHealthCheckConfig = inspectResult;
    return (inspectWithHealthCheckConfig.Config?.Healthcheck ??
        inspectWithHealthCheckConfig.Config?.HealthCheck ??
        inspectWithHealthCheckConfig.ContainerConfig?.Healthcheck ??
        inspectWithHealthCheckConfig.ContainerConfig?.HealthCheck ??
        inspectWithHealthCheckConfig.Healthcheck ??
        inspectWithHealthCheckConfig.HealthCheck);
};
exports.getHealthCheckConfig = getHealthCheckConfig;
const hasHealthCheckConfig = (inspectResult) => {
    return (0, exports.hasHealthCheck)((0, exports.getHealthCheckConfig)(inspectResult));
};
exports.hasHealthCheckConfig = hasHealthCheckConfig;
const hasDisabledHealthCheckConfig = (inspectResult) => {
    return (0, exports.isHealthCheckDisabled)((0, exports.getHealthCheckConfig)(inspectResult));
};
exports.hasDisabledHealthCheckConfig = hasDisabledHealthCheckConfig;
const getHealthCheckStatusFromInspect = (inspectResult) => {
    const state = inspectResult.State;
    const status = state.Health?.Status ?? state.Healthcheck?.Status;
    return status === undefined || status === "" ? undefined : status;
};
exports.getHealthCheckStatusFromInspect = getHealthCheckStatusFromInspect;
const hasHealthCheckStatus = (inspectResult) => {
    return (0, exports.getHealthCheckStatusFromInspect)(inspectResult) !== undefined;
};
exports.hasHealthCheckStatus = hasHealthCheckStatus;
