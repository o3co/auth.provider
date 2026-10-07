"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FixedPortGenerator = exports.RandomPortGenerator = void 0;
class RandomPortGenerator {
    async generatePort() {
        const { default: getPort } = await import("get-port");
        return getPort();
    }
}
exports.RandomPortGenerator = RandomPortGenerator;
class FixedPortGenerator {
    ports;
    portIndex = 0;
    constructor(ports) {
        this.ports = ports;
    }
    generatePort() {
        return Promise.resolve(this.ports[this.portIndex++]);
    }
}
exports.FixedPortGenerator = FixedPortGenerator;
