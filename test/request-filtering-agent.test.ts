import * as assert from "assert";
import fetch from "node-fetch";
import { globalHttpAgent, RequestFilteringHttpAgent, useAgent } from "../src/request-filtering-agent";
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
            allowPrivateIP: true
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
    it("should allow http://127.0.0.1, but other private ip is disallowed", async () => {
        const agent = new RequestFilteringHttpAgent({
            allowIPAddressList: ["127.0.0.1"],
            allowPrivateIP: false
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
            `http://017700000001:${TEST_PORT}`, // long ip - lookup
            `http://127.0.0.1.xip.io:${TEST_PORT}/`, // wildcard domain
            // `https://127.0.0.1.nip.io:${TEST_PORT}/`,
            `http://localhost:${TEST_PORT}`
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
    // FIXME:
    it("should not request because it is not resolve - timeout", async () => {
        const privateIPs = [
            // link address
            `http://169.254.169.254:${TEST_PORT}`,
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
                assert.ok(/EHOSTDOWN/i.test(error.message), `Failed at ${ipAddress}, error: ${error}`);
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
