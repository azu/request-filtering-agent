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
    describe("filter", () => {
        it("should pass the normalized address and the raw address to filter", async () => {
            const calls: { address: string; raw: string; family: number; host?: string; range: string }[] = [];
            const agent = new RequestFilteringHttpAgent({
                allowPrivateIPAddress: true,
                filter: (address, context) => {
                    calls.push({ address, ...context });
                    return false;
                }
            });
            // IPv4-mapped IPv6 address is normalized to IPv4 address
            // filter returns false to avoid depending on IPv6 support of the environment
            await assert.rejects(fetch(`http://[::ffff:127.0.0.1]:${TEST_PORT}`, { agent, timeout: 2000 }), {
                message: /Because It is rejected by filter/
            });
            assert.deepStrictEqual(calls, [
                { address: "127.0.0.1", raw: "::ffff:7f00:1", family: 4, host: undefined, range: "loopback" }
            ]);
        });
        it("should pass the requested hostname to filter after DNS lookup", async () => {
            const calls: { address: string; host?: string }[] = [];
            const agent = new RequestFilteringHttpAgent({
                allowPrivateIPAddress: true,
                filter: (address, { host }) => {
                    calls.push({ address, host });
                    return true;
                }
            });
            await fetch(`http://localhost:${TEST_PORT}`, { agent, timeout: 2000 });
            assert.ok(calls.length > 0);
            for (const call of calls) {
                assert.strictEqual(call.host, "localhost");
                assert.ok(["127.0.0.1", "::1"].includes(call.address), `unexpected address: ${call.address}`);
            }
        });
        it("should allow only 127.0.0.1 by filter, but other private ip is disallowed", async () => {
            const agent = new RequestFilteringHttpAgent({
                allowPrivateIPAddress: true,
                filter: (address, { range }) => range === "unicast" || address === "127.0.0.1"
            });
            const res = await fetch(`http://127.0.0.1:${TEST_PORT}`, { agent, timeout: 2000 });
            assert.strictEqual(res.status, 200);
            await assert.rejects(fetch(`http://127.0.0.2:${TEST_PORT}`, { agent, timeout: 2000 }), {
                message: /Because It is rejected by filter/
            });
        });
        it("should block the request when filter returns a truthy non-boolean value", async () => {
            const agent = new RequestFilteringHttpAgent({
                allowPrivateIPAddress: true,
                // @ts-expect-error - filter should return boolean
                filter: () => 1
            });
            await assert.rejects(fetch(`http://127.0.0.1:${TEST_PORT}`, { agent, timeout: 2000 }), {
                message: /Because It is rejected by filter/
            });
        });
        it("should block the request when filter throws an error", async () => {
            const agent = new RequestFilteringHttpAgent({
                allowPrivateIPAddress: true,
                filter: () => {
                    throw new Error("filter error");
                }
            });
            await assert.rejects(fetch(`http://127.0.0.1:${TEST_PORT}`, { agent, timeout: 2000 }), {
                message: /filter error/
            });
        });
        it("should not call filter when the built-in check blocks the address", async () => {
            let called = false;
            const agent = new RequestFilteringHttpAgent({
                filter: () => {
                    called = true;
                    return true;
                }
            });
            await assert.rejects(fetch(`http://127.0.0.1:${TEST_PORT}`, { agent, timeout: 2000 }), {
                message: /It is private IP address/
            });
            assert.strictEqual(called, false);
        });
        it("should apply filter to the https agent", async () => {
            const agent = new RequestFilteringHttpsAgent({
                allowPrivateIPAddress: true,
                filter: () => false
            });
            await assert.rejects(fetch(`https://127.0.0.1:${TEST_PORT}`, { agent, timeout: 2000 }), {
                message: /Because It is rejected by filter/
            });
        });
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
