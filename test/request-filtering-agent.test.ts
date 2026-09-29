import { describe, it, beforeEach, afterEach } from "node:test";
import * as assert from "node:assert/strict";
import fetch from "node-fetch";
import {
    globalHttpAgent,
    RequestFilteringHttpAgent,
    RequestFilteringHttpsAgent,
    useAgent
} from "../src/request-filtering-agent.ts";
import * as http from "node:http";
import * as https from "node:https";

const TEST_PORT = 12456;
const IS_IPV6_SUPPORTED = true;
describe("request-filtering-agent", function () {
    let close = () => {
        return Promise.resolve();
    };
    beforeEach(() => {
        return new Promise<void>((resolve) => {
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
        const privateIPs = [`http://127.0.0.1:${TEST_PORT}`];
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
    it("0.0.0.0 and :: is metaAddress, it is disabled by default", async () => {
        const agent = new RequestFilteringHttpAgent();
        const disAllowedIPs = [`http://0.0.0.0:${TEST_PORT}`, `http://[::]:${TEST_PORT}`];
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
            allowIPAddressList: ["127.0.0.1", "::1"],
            allowPrivateIPAddress: false
        });
        const privateIPs = [`http://127.0.0.1:${TEST_PORT}`, `http://localhost:${TEST_PORT}`];
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
        const disAllowedPrivateIPs = [`http://169.254.169.254:${TEST_PORT}`];
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
    it("should allow CIDR range in allowIPAddressList", async () => {
        const agent = new RequestFilteringHttpAgent({
            allowIPAddressList: ["127.0.0.0/8", "::1"],
            allowPrivateIPAddress: false
        });
        const privateIPs = [`http://127.0.0.1:${TEST_PORT}`, `http://localhost:${TEST_PORT}`];
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
        const disAllowedPrivateIPs = [`http://169.254.169.254:${TEST_PORT}`];
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
    it("should log a warning for invalid CIDR in allowIPAddressList", async (t) => {
        const agent = new RequestFilteringHttpAgent({
            allowIPAddressList: ["127.0.0.0/invalid"],
            allowPrivateIPAddress: false
        });
        const privateIPs = [`http://127.0.0.1:${TEST_PORT}`];
        const consoleMock = t.mock.method(console, "warn");
        for (const ipAddress of privateIPs) {
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
        assert.strictEqual(consoleMock.mock.calls.length, 1);
        const error = consoleMock.mock.calls[0].arguments[0] as Error;
        assert.strictEqual(
            error.message,
            "[request-filtering-agent] Invalid CIDR in allowIPAddressList: 127.0.0.0/invalid"
        );
        assert.ok(error.cause);
    });
    it("should deny CIDR range in denyIPAddressList", async () => {
        const agent = new RequestFilteringHttpAgent({
            allowPrivateIPAddress: true,
            denyIPAddressList: ["127.0.0.0/8"]
        });
        const deniedIPs = [`http://127.0.0.1:${TEST_PORT}`, `http://127.0.0.2:${TEST_PORT}`];
        for (const ipAddress of deniedIPs) {
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
    it("should log a warning for invalid CIDR in denyIPAddressList", async (t) => {
        const agent = new RequestFilteringHttpAgent({
            allowPrivateIPAddress: true,
            denyIPAddressList: ["127.0.0.0/invalid"]
        });
        const privateIPs = [`http://127.0.0.1:${TEST_PORT}`];
        const consoleMock = t.mock.method(console, "warn");
        for (const ipAddress of privateIPs) {
            try {
                await fetch(ipAddress, {
                    agent,
                    timeout: 2000
                });
            } catch (error) {
                // Should still connect since the CIDR is invalid
            }
        }
        assert.strictEqual(consoleMock.mock.calls.length, 1);
        const error = consoleMock.mock.calls[0].arguments[0] as Error;
        assert.strictEqual(
            error.message,
            "[request-filtering-agent] Invalid CIDR in denyIPAddressList: 127.0.0.0/invalid"
        );
        assert.ok(error.cause);
    });
    it("should deny IPv4-mapped IPv6 address that matches IPv4 in denyIPAddressList", async () => {
        const requestError = (hostname: string, denyIPAddressList: string[]) => {
            const agent = new RequestFilteringHttpAgent({
                allowPrivateIPAddress: true,
                denyIPAddressList
            });
            return new Promise<Error>((resolve, reject) => {
                const req = http.get({ hostname, port: TEST_PORT, agent });
                req.on("error", resolve);
                req.on("response", () => reject(new Error("SHOULD NOT BE CALLED")));
            });
        };
        const hostnames = ["::ffff:127.0.0.1", "::ffff:7f00:1", "0:0:0:0:0:ffff:7f00:1"];
        const denyLists = [["127.0.0.1"], ["127.0.0.0/8"], ["::ffff:127.0.0.1"], ["::ffff:127.0.0.0/104"]];
        for (const hostname of hostnames) {
            for (const denyIPAddressList of denyLists) {
                const error = await requestError(hostname, denyIPAddressList);
                assert.match(error.message, /It is defined in denyIPAddressList/, `${hostname} ${denyIPAddressList}`);
            }
        }
        // IPv4 address should also match IPv4-mapped IPv6 entry
        const error = await requestError("127.0.0.1", ["::ffff:127.0.0.1"]);
        assert.match(error.message, /It is defined in denyIPAddressList/);
    });
    it("should deny IPv6 address that is written in a different form in denyIPAddressList", async () => {
        const agent = new RequestFilteringHttpAgent({
            allowPrivateIPAddress: true,
            denyIPAddressList: ["::1"]
        });
        const error = await new Promise<Error>((resolve, reject) => {
            const req = http.get({ hostname: "0:0:0:0:0:0:0:1", port: TEST_PORT, agent });
            req.on("error", resolve);
            req.on("response", () => reject(new Error("SHOULD NOT BE CALLED")));
        });
        assert.match(error.message, /It is defined in denyIPAddressList/);
    });
    it("should not warn when CIDR in denyIPAddressList is different address family", async (t) => {
        const agent = new RequestFilteringHttpAgent({
            allowPrivateIPAddress: true,
            denyIPAddressList: ["fc00::/7", "10.0.0.0/8"]
        });
        const consoleMock = t.mock.method(console, "warn");
        await fetch(`http://127.0.0.1:${TEST_PORT}`, { agent, timeout: 2000 });
        assert.strictEqual(consoleMock.mock.calls.length, 0);
    });
    it("IPv4-mapped IPv6: should not request because it is private IP", async () => {
        for (const hostname of ["::ffff:127.0.0.1", "::ffff:a9fe:a9fe"]) {
            const error = await new Promise<Error>((resolve, reject) => {
                const req = http.get({ hostname, port: TEST_PORT, agent: new RequestFilteringHttpAgent() });
                req.on("error", resolve);
                req.on("response", () => reject(new Error("SHOULD NOT BE CALLED")));
            });
            assert.match(error.message, /It is private IP address/);
        }
    });
    it("IPv4: should not request because it is private IP", async () => {
        const privateIPs = [
            `http://127.0.0.1:${TEST_PORT}`, //
            `http://A.com@127.0.0.1:${TEST_PORT}`
        ];
        for (const ipAddress of privateIPs) {
            try {
                await fetch(ipAddress, {
                    agent: useAgent(ipAddress),
                    timeout: 2000
                });
                throw new ReferenceError("SHOULD NOT BE CALLED");
            } catch (error: any) {
                if (error instanceof ReferenceError) {
                    assert.fail(error);
                }
                // should be validation error
                assert.match(error.message, /It is private IP address/);
            }
        }
    });
    it("IPv4: should emit request error for literal private IP instead of throwing synchronously", async () => {
        const agent = new RequestFilteringHttpAgent();
        await new Promise<void>((resolve, reject) => {
            let req: http.ClientRequest;
            try {
                req = http.get({
                    hostname: "169.254.169.254",
                    port: 80,
                    agent
                });
            } catch (error) {
                reject(error);
                return;
            }
            req.on("error", (error) => {
                try {
                    assert.match(error.message, /It is private IP address/);
                    resolve();
                } catch (assertionError) {
                    reject(assertionError);
                }
            });
            req.on("response", () => {
                reject(new Error("SHOULD NOT BE CALLED"));
            });
        });
    });
    it("HTTPS IPv4: should emit request error for literal private IP instead of throwing synchronously", async () => {
        const agent = new RequestFilteringHttpsAgent();
        await new Promise<void>((resolve, reject) => {
            let req: http.ClientRequest;
            try {
                req = https.get({
                    hostname: "169.254.169.254",
                    port: 443,
                    agent
                });
            } catch (error) {
                reject(error);
                return;
            }
            req.on("error", (error) => {
                try {
                    assert.match(error.message, /It is private IP address/);
                    resolve();
                } catch (assertionError) {
                    reject(assertionError);
                }
            });
            req.on("response", () => {
                reject(new Error("SHOULD NOT BE CALLED"));
            });
        });
    });
    it("IPv4: should not request because it is meta/unspecified IP", async () => {
        const privateIPs = [
            `http://0.0.0.0:${TEST_PORT}` // 0.0.0.0 is special
        ];
        for (const ipAddress of privateIPs) {
            try {
                await fetch(ipAddress, {
                    agent: useAgent(ipAddress),
                    timeout: 2000
                });
                throw new ReferenceError("SHOULD NOT BE CALLED");
            } catch (error: any) {
                if (error instanceof ReferenceError) {
                    assert.fail(error);
                }
                // should be validation error
                assert.match(error.message, /It is meta IP address/);
            }
        }
    });
    // TODO: Travis CI does not support IPv6
    // https://docs.travis-ci.com/user/reference/overview/
    // https://github.com/travis-ci/travis-ci/issues/8891
    it("IPv6: should not request because Socket is closed", { skip: !IS_IPV6_SUPPORTED }, async () => {
        const privateIPs = [
            `http://[::1]:${TEST_PORT}`, // IPv6
            `http://[0:0:0:0:0:0:0:1]:${TEST_PORT}`, // IPv6 explicitly
            `http://[0:0:0:0:0:ffff:127.0.0.1]:${TEST_PORT}`, // IPv4-mapped IPv6 addresses
            `http://[::ffff:127.0.0.1]:${TEST_PORT}`, // IPv4-mapped IPv6 addresses
            `http://[::ffff:7f00:1]:${TEST_PORT}` // IPv4-mapped IPv6 addresses
        ];
        for (const ipAddress of privateIPs) {
            try {
                await fetch(ipAddress, {
                    agent: useAgent(ipAddress),
                    timeout: 2000
                });
                throw new ReferenceError("SHOULD NOT BE CALLED");
            } catch (error: any) {
                if (error instanceof ReferenceError) {
                    assert.fail(error);
                }
                // should be validation error
                assert.match(error.message, /It is private IP address/);
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
            `http://localhost`,
            `https://localhost`,
            `http://bit.ly/3z04dcF` // redirect to http://127.0.0.1.nip.io:12456
        ];
        for (const ipAddress of privateIPs) {
            try {
                await fetch(ipAddress, {
                    agent: useAgent(ipAddress),
                    timeout: 10_000
                });
                throw new ReferenceError("SHOULD NOT BE CALLED");
            } catch (error: any) {
                if (error instanceof ReferenceError) {
                    assert.fail(error);
                }
                assert.ok(
                    /Because, It is private IP address./i.test(error.message),
                    `Failed at ${ipAddress}, error: ${error}`
                );
            }
        }
    });
    // FIXME: timout is not testable
    it("should not request because it is not resolve - timeout", async () => {
        const privateIPs = [
            // link address
            `http://169.254.169.254`,
            `http://169.254.169.254.nip.io`,
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
            } catch (error: any) {
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
                timeout: 10_000
            });
        } catch (error) {
            assert.fail(new Error("should fetch public ip, but it is failed"));
        }
    });
});
