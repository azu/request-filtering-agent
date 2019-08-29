import * as assert from "assert";
import fetch from "node-fetch";
import {
    globalHttpAgent,
    RequestFilteringHttpAgent,
    useAgent,
    applyRequestFilter
} from "../src/request-filtering-agent";
import * as http from "http";

const TEST_PORT = 12456;
describe("request-filtering-agent", function() {
    let close = () => {
        return Promise.resolve();
    };
    beforeEach(() => {
        return new Promise((resolve) => {
            // response ok
            const server = http.createServer();
            server.on("request", (_req, res) => {
                res.writeHead(200, { "Content-Type": "text/plain" });
                res.write("ok");
                res.end();
            });
            close = () => {
                return new Promise((resolve, reject) => {
                    server.close((error) => {
                        if (error) {
                            reject(error);
                        } else {
                            resolve();
                        }
                    });
                });
            };
            server.listen(TEST_PORT, () => {
                resolve();
            });
        });
    });
    afterEach(() => {
        return close();
    });
    it("should request local ip address with allowPrivateIP: true", async () => {
        const agent = new RequestFilteringHttpAgent({
            allowPrivateIPAddress: true
        });
        const privateIPs = [
            `http://127.0.0.1:${TEST_PORT}`
        ];
        for (const ipAddress of privateIPs) {
            try {
                await fetch(ipAddress, {
                    agent,
                    timeout: 2000
                });
            } catch (error) {
                assert.fail(new Error("should fetch, because it is allow"));
            }
        }
    });
    it("apply request filtering to existing http.Agent", async () => {
        const agent = new http.Agent({
            keepAlive: true
        });
        const agentWithFiltering = applyRequestFilter(agent, {
            allowPrivateIPAddress: true
        });
        const privateIPs = [
            `http://127.0.0.1:${TEST_PORT}`
        ];
        for (const ipAddress of privateIPs) {
            try {
                await fetch(ipAddress, {
                    agent: agentWithFiltering,
                    timeout: 2000
                });
            } catch (error) {
                assert.fail(new Error("should fetch, because it is allow, error" + error));
            }
        }
    });
    it("0.0.0.0 and :: is metaAddress, it is disabled by default", async () => {
        const agent = new RequestFilteringHttpAgent();
        const disAllowedIPs = [
            `http://0.0.0.0:${TEST_PORT}`,
            `http://[::]:${TEST_PORT}`
        ];
        for (const ipAddress of disAllowedIPs) {
            try {
                await fetch(ipAddress, {
                    agent,
                    timeout: 2000
                });
                throw new ReferenceError("SHOULD NOT BE CALLED:" + ipAddress);
            } catch (error) {
                if (error instanceof ReferenceError) {
                    assert.fail(error);
                }
            }
        }
    });

    it("should allow http://127.0.0.1, but other private ip is disallowed", async () => {
        const agent = new RequestFilteringHttpAgent({
            allowIPAddressList: ["127.0.0.1"],
            allowPrivateIPAddress: false
        });
        const privateIPs = [
            `http://127.0.0.1:${TEST_PORT}`,
            `http://localhost:${TEST_PORT}`
        ];
        for (const ipAddress of privateIPs) {
            try {
                await fetch(ipAddress, {
                    agent,
                    timeout: 2000
                });
            } catch (error) {
                assert.fail(new Error("should fetch, because it is allow, error" + error));
            }
        }
        const disAllowedPrivateIPs = [
            `http://169.254.169.254:${TEST_PORT}`
        ];
        for (const ipAddress of disAllowedPrivateIPs) {
            try {
                await fetch(ipAddress, {
                    agent,
                    timeout: 2000
                });
                throw new ReferenceError("SHOULD NOT BE CALLED");
            } catch (error) {
                if (error instanceof ReferenceError) {
                    assert.fail(error);
                }
            }
        }
    });
    it("should not request because Socket is closed", async () => {
        const privateIPs = [
            `http://0.0.0.0:${TEST_PORT}`, // 0.0.0.0 is special
            `http://127.0.0.1:${TEST_PORT}`, //
            `http://A.com@127.0.0.1:${TEST_PORT}` //
        ];
        for (const ipAddress of privateIPs) {
            try {
                await fetch(ipAddress, {
                    agent: useAgent(ipAddress),
                    timeout: 2000
                });
                throw new ReferenceError("SHOULD NOT BE CALLED");
            } catch (error) {
                if (error instanceof ReferenceError) {
                    assert.fail(error);
                }
                assert.ok(/Socket is closed/i.test(error.message), `Failed at ${ipAddress}, error: ${error}`);
            }
        }
    });
    it("should not request because the dns-lookuped address is private", async () => {
        const privateIPs = [
            // https://www.psyon.org/tools/ip_address_converter.php?ip=127.0.0.1
            `http://127.0.1:${TEST_PORT}`, // Decimal
            `http://127.1:${TEST_PORT}`, // Decimal
            // `http://21307064331:${TEST_PORT}`, // Decimal
            // `http://0177.00.00.01:${TEST_PORT}`, // Octal
            `http://0177.00.01:${TEST_PORT}`, // Octal
            `http://0177.01:${TEST_PORT}`, // Octal
            `http://017700000001:${TEST_PORT}`, // Octal
            `http://0x7f.0x0.0x0.0x1:${TEST_PORT}`, // Hexidecimal
            `http://0x7f.0x0.0x1:${TEST_PORT}`, // Hexidecimal
            `http://0x7f.0x1:${TEST_PORT}`, // Hexidecimal
            `http://0x7f000001:${TEST_PORT}`, // Hexidecimal
            `http://127.0.0.1.nip.io:${TEST_PORT}/`, // wildcard domain
            `https://127.0.0.1.nip.io:${TEST_PORT}/`, // wildcard domain
            `http://localhost:${TEST_PORT}`,
        ];
        for (const ipAddress of privateIPs) {
            try {
                await fetch(ipAddress, {
                    agent: useAgent(ipAddress),
                    timeout: 2000
                });
                throw new ReferenceError("SHOULD NOT BE CALLED");
            } catch (error) {
                if (error instanceof ReferenceError) {
                    assert.fail(error);
                }
                assert.ok(/It is private IP address/i.test(error.message), `Failed at ${ipAddress}, error: ${error}`);
            }
        }
    });
    // FIXME: timout is not testable
    it("should not request because it is not resolve - timeout", async () => {
        const privateIPs = [
            // link address
            `http://169.254.169.254`,
            `http://169.254.169.254.xip.io`,
            // aws
            `http://169.254.169.254/latest/user-data`,
            // gcp
            `http://169.254.169.254/computeMetadata/v1/`
        ];
        for (const ipAddress of privateIPs) {
            try {
                await fetch(ipAddress, {
                    agent: useAgent(ipAddress),
                    timeout: 2000
                });
                throw new ReferenceError("SHOULD NOT BE CALLED");
            } catch (error) {
                if (error instanceof ReferenceError) {
                    assert.fail(error);
                }
            }
        }
    });
    it("should request public ip address", async () => {
        try {
            await fetch("http://example.com", {
                agent: globalHttpAgent,
                timeout: 2000
            });
        } catch (error) {
            assert.fail(new Error("should fetch public ip, but it is failed"));
        }
    });
});
