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
import * as os from "node:os";
import { startTestDnsServer, type DnsRecords, type TestDnsServer } from "./helper/dns-server.ts";
import * as net from "node:net";

const TEST_PORT = 12456;
// Detect IPv6 support from network interfaces. Some CI and container environments disable IPv6.
const IS_IPV6_SUPPORTED = Object.values(os.networkInterfaces())
    .flat()
    .some((networkInterface) => networkInterface?.family === "IPv6");
// E2E tests use real DNS and connect to the Internet. They run by default.
// Set SKIP_NETWORK_TEST=1 to skip them in an environment without the Internet access
const IS_NETWORK_TEST_SKIPPED = process.env.SKIP_NETWORK_TEST === "1";
// DNS records of the test DNS server. The tests send real DNS queries to it instead of external DNS
const TEST_DNS_RECORDS = {
    "allowed.test": ["127.0.0.1"],
    "loopback.test": ["127.0.0.1"],
    "redirect-target.test": ["127.0.0.2"],
    "private.test": ["192.168.0.1"],
    "metadata.test": ["169.254.169.254"],
    "meta.test": ["0.0.0.0"],
    "loopback-v6.test": ["::1"],
    "unique-local-v6.test": ["fd00::1"],
    "ipv4-mapped-v6.test": ["::ffff:127.0.0.1"],
    "ipv4-compatible-v6.test": ["::7f00:1"],
    // public address and private address
    "mixed.test": ["93.184.215.14", "127.0.0.1"]
} satisfies DnsRecords;
describe("request-filtering-agent", function () {
    let close = () => {
        return Promise.resolve();
    };
    let dnsServer: TestDnsServer;
    beforeEach(async () => {
        dnsServer = await startTestDnsServer(TEST_DNS_RECORDS);
        return new Promise<void>((resolve) => {
            // response ok
            const server = http.createServer();
            server.on("request", (req, res) => {
                if (req.url === "/redirect-to-private") {
                    res.writeHead(302, { Location: `http://redirect-target.test:${TEST_PORT}/` });
                    res.end();
                    return;
                }
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
    afterEach(async () => {
        await dnsServer.close();
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
    it("should match mixed IPv4/IPv6 CIDRs in allowIPAddressList without warning", async (t) => {
        const agent = new RequestFilteringHttpAgent({
            allowIPAddressList: ["fd00::/8", "127.0.0.0/8", "10.0.0.0/8", "::1/128"],
            allowPrivateIPAddress: false
        });
        const consoleMock = t.mock.method(console, "warn");
        const allowedIPs = [`http://127.0.0.1:${TEST_PORT}`];
        if (IS_IPV6_SUPPORTED) {
            allowedIPs.push(`http://[::1]:${TEST_PORT}`);
        }
        for (const ipAddress of allowedIPs) {
            try {
                await fetch(ipAddress, {
                    agent,
                    timeout: 2000
                });
            } catch (error) {
                assert.fail(new Error("should fetch, because it is allow, error" + error));
            }
        }
        assert.strictEqual(consoleMock.mock.calls.length, 0);
    });
    it("should not treat a CIDR of the other address family as invalid", async (t) => {
        const agent = new RequestFilteringHttpAgent({
            allowIPAddressList: ["fd00::/8"],
            denyIPAddressList: ["fd00::/8"],
            allowPrivateIPAddress: false
        });
        const consoleMock = t.mock.method(console, "warn");
        try {
            await fetch(`http://127.0.0.1:${TEST_PORT}`, {
                agent,
                timeout: 2000
            });
            throw new ReferenceError("SHOULD NOT BE CALLED");
        } catch (error) {
            if (error instanceof ReferenceError) {
                assert.fail(error);
            }
        }
        assert.strictEqual(consoleMock.mock.calls.length, 0);
    });
    it("should deny with mixed IPv4/IPv6 CIDRs in denyIPAddressList without warning", async (t) => {
        const agent = new RequestFilteringHttpAgent({
            allowPrivateIPAddress: true,
            denyIPAddressList: ["fd00::/8", "127.0.0.0/8"]
        });
        const consoleMock = t.mock.method(console, "warn");
        try {
            await fetch(`http://127.0.0.1:${TEST_PORT}`, {
                agent,
                timeout: 2000
            });
            throw new ReferenceError("SHOULD NOT BE CALLED");
        } catch (error) {
            if (error instanceof ReferenceError) {
                assert.fail(error);
            }
        }
        assert.strictEqual(consoleMock.mock.calls.length, 0);
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
        it("should pass a non-unicast range for IPv6 address outside of 2000::/3", async () => {
            const ranges: string[] = [];
            const agent = new RequestFilteringHttpAgent({
                allowPrivateIPAddress: true,
                filter: (_address, { range }) => {
                    ranges.push(range);
                    return range === "unicast";
                }
            });
            // IPv4-compatible IPv6 address of 127.0.0.1. ipaddr.js treats it as "unicast"
            await assert.rejects(fetch(`http://[::7f00:1]:${TEST_PORT}`, { agent, timeout: 2000 }), {
                message: /Because It is rejected by filter/
            });
            assert.deepStrictEqual(ranges, ["reserved"]);
        });
        it("should pass the requested hostname to filter after DNS lookup", async () => {
            const calls: { address: string; host?: string }[] = [];
            const agent = new RequestFilteringHttpAgent({
                lookup: dnsServer.lookup,
                allowPrivateIPAddress: true,
                filter: (address, { host }) => {
                    calls.push({ address, host });
                    return true;
                }
            });
            await fetch(`http://allowed.test:${TEST_PORT}`, { agent, timeout: 2000 });
            assert.deepStrictEqual(calls, [{ address: "127.0.0.1", host: "allowed.test" }]);
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
        it("should block the request when filter throws a non-Error value", async () => {
            // A falsy thrown value must not be treated as "no error"
            for (const thrownValue of [undefined, null, "", 0, "string"]) {
                const agent = new RequestFilteringHttpAgent({
                    lookup: dnsServer.lookup,
                    allowPrivateIPAddress: true,
                    filter: () => {
                        throw thrownValue;
                    }
                });
                // literal IP address and the address resolved by DNS
                for (const url of [`http://127.0.0.1:${TEST_PORT}`, `http://allowed.test:${TEST_PORT}`]) {
                    await assert.rejects(
                        fetch(url, { agent, timeout: 2000 }),
                        { message: /Because filter throws a non-Error value/ },
                        `thrown value: ${String(thrownValue)}, url: ${url}`
                    );
                }
            }
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
        it("should support CIDR with net.BlockList in filter", async () => {
            const allowList = new net.BlockList();
            allowList.addSubnet("127.0.0.0", 8, "ipv4");
            const agent = new RequestFilteringHttpAgent({
                allowPrivateIPAddress: true,
                filter: (address, { family, range }) =>
                    range === "unicast" || allowList.check(address, family === 4 ? "ipv4" : "ipv6")
            });
            const res = await fetch(`http://127.0.0.2:${TEST_PORT}`, { agent, timeout: 2000 });
            assert.strictEqual(res.status, 200);
            await assert.rejects(fetch(`http://169.254.169.254:${TEST_PORT}`, { agent, timeout: 2000 }), {
                message: /Because It is rejected by filter/
            });
        });
        it("should apply filter to the address that is allowed by allowIPAddressList", async () => {
            const agent = new RequestFilteringHttpAgent({
                allowIPAddressList: ["127.0.0.1"],
                filter: () => false
            });
            await assert.rejects(fetch(`http://127.0.0.1:${TEST_PORT}`, { agent, timeout: 2000 }), {
                message: /Because It is rejected by filter/
            });
        });
        it("should block the request when filter returns a Promise", async () => {
            const agent = new RequestFilteringHttpAgent({
                allowPrivateIPAddress: true,
                // @ts-expect-error - filter should return boolean synchronously
                filter: async () => true
            });
            await assert.rejects(fetch(`http://127.0.0.1:${TEST_PORT}`, { agent, timeout: 2000 }), {
                message: /Because It is rejected by filter/
            });
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
            `http://[::ffff:7f00:1]:${TEST_PORT}`, // IPv4-mapped IPv6 addresses
            `http://[::127.0.0.1]:${TEST_PORT}`, // IPv4-compatible IPv6 addresses (normalized to ::7f00:1)
            `http://[::7f00:1]:${TEST_PORT}`, // IPv4-compatible IPv6 addresses
            `http://[::169.254.169.254]:${TEST_PORT}`, // IPv4-compatible IPv6 addresses
            `http://[::192.168.0.1]:${TEST_PORT}`, // IPv4-compatible IPv6 addresses
            `http://[::8.8.8.8]:${TEST_PORT}`, // IPv4-compatible IPv6 addresses (deprecated, block all)
            `http://[64:ff9b:1::127.0.0.1]:${TEST_PORT}`, // Local-use NAT64 prefix (RFC 8215)
            `http://[fec0::1]:${TEST_PORT}`, // deprecated site-local
            `http://[5f00::1]:${TEST_PORT}` // outside of 2000::/3 (not allocated as Global Unicast)
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
            `http://localhost:${TEST_PORT}`,
            `http://localhost`,
            `https://localhost`
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
    // E2E: use real DNS and the Internet
    it(
        "E2E: should not request because the address resolved by real DNS is private",
        { skip: IS_NETWORK_TEST_SKIPPED },
        async () => {
            const privateIPs = [
                `http://127.0.0.1.nip.io:${TEST_PORT}/`, // wildcard domain
                `https://127.0.0.1.nip.io:${TEST_PORT}/`, // wildcard domain
                `http://169.254.169.254.nip.io` // wildcard domain
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
        }
    );
    it("should not request because the address resolved by DNS is private", async () => {
        const hostnames = Object.keys(TEST_DNS_RECORDS).filter((hostname) => hostname !== "allowed.test");
        for (const hostname of hostnames) {
            const urls = [`http://${hostname}:${TEST_PORT}/`, `https://${hostname}:${TEST_PORT}/`];
            for (const url of urls) {
                const agent = url.startsWith("https")
                    ? new RequestFilteringHttpsAgent({ lookup: dnsServer.lookup })
                    : new RequestFilteringHttpAgent({ lookup: dnsServer.lookup });
                try {
                    await fetch(url, {
                        agent,
                        timeout: 2000
                    });
                    throw new ReferenceError("SHOULD NOT BE CALLED");
                } catch (error: any) {
                    if (error instanceof ReferenceError) {
                        assert.fail(new Error(`Failed at ${url}: it should be blocked`));
                    }
                    assert.match(
                        error.message,
                        /is not allowed\. Because, It is (private|meta) IP address\./,
                        `Failed at ${url}, error: ${error}`
                    );
                    assert.ok(
                        error.message.includes(`host:${hostname}`),
                        `Failed at ${url}: error message should include the hostname, error: ${error}`
                    );
                }
            }
            // the test DNS server should receive the query
            assert.ok(dnsServer.queriedHostnames.includes(hostname), `${hostname} should be queried`);
        }
    });
    it("should request the address resolved by DNS when it is in allowIPAddressList", async () => {
        const agent = new RequestFilteringHttpAgent({
            lookup: dnsServer.lookup,
            allowIPAddressList: ["127.0.0.1"]
        });
        const res = await fetch(`http://allowed.test:${TEST_PORT}/`, {
            agent,
            timeout: 2000
        });
        assert.strictEqual(res.status, 200);
        assert.ok(dnsServer.queriedHostnames.includes("allowed.test"));
    });
    it("should not follow a redirect to the hostname that is resolved to private address", async () => {
        // allowed.test (127.0.0.1) is allowed, but it redirects to redirect-target.test (127.0.0.2)
        const agent = new RequestFilteringHttpAgent({
            lookup: dnsServer.lookup,
            allowIPAddressList: ["127.0.0.1"]
        });
        try {
            await fetch(`http://allowed.test:${TEST_PORT}/redirect-to-private`, {
                agent,
                timeout: 2000
            });
            throw new ReferenceError("SHOULD NOT BE CALLED");
        } catch (error: any) {
            if (error instanceof ReferenceError) {
                assert.fail(error);
            }
            assert.match(
                error.message,
                /DNS lookup 127\.0\.0\.2\(family:4, host:redirect-target\.test\) is not allowed/
            );
        }
    });
    // FIXME: timout is not testable
    it("should not request because it is not resolve - timeout", async () => {
        const privateIPs = [
            // link address
            `http://169.254.169.254`,
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
    it("E2E: should request public ip address", { skip: IS_NETWORK_TEST_SKIPPED }, async () => {
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
