import * as dgram from "node:dgram";
import * as dns from "node:dns";
import type { LookupFunction } from "node:net";
import ipaddr from "ipaddr.js";

const TYPE_A = 1;
const TYPE_AAAA = 28;
const CLASS_IN = 1;

export type DnsRecords = Record<string, string[]>;
export type TestDnsServer = {
    // dns.lookup compatible function that asks the test DNS server
    lookup: LookupFunction;
    // hostnames that the test DNS server received
    queriedHostnames: string[];
    close: () => Promise<void>;
};

const readQuestion = (message: Buffer) => {
    const labels: string[] = [];
    let offset = 12; // skip header
    while (message[offset] !== 0) {
        const length = message[offset];
        labels.push(message.subarray(offset + 1, offset + 1 + length).toString("ascii"));
        offset += 1 + length;
    }
    const type = message.readUInt16BE(offset + 1);
    // question = QNAME + QTYPE(2) + QCLASS(2)
    return { name: labels.join(".").toLowerCase(), type, end: offset + 5 };
};

const createResponse = (query: Buffer, records: DnsRecords): { response: Buffer; name: string } => {
    const { name, type, end } = readQuestion(query);
    const addresses = records[name];
    const answers = (addresses ?? [])
        .map((address) => ipaddr.parse(address))
        .filter((address) =>
            type === TYPE_A ? address.kind() === "ipv4" : type === TYPE_AAAA && address.kind() === "ipv6"
        )
        .map((address) => {
            const rdata = Buffer.from(address.toByteArray());
            const answer = Buffer.alloc(12);
            answer.writeUInt16BE(0xc00c, 0); // pointer to QNAME
            answer.writeUInt16BE(type, 2);
            answer.writeUInt16BE(CLASS_IN, 4);
            answer.writeUInt32BE(0, 6); // TTL
            answer.writeUInt16BE(rdata.length, 10);
            return Buffer.concat([answer, rdata]);
        });
    const header = Buffer.alloc(12);
    query.copy(header, 0, 0, 2); // ID
    // QR=1, RD=1, RA=1. RCODE=3(NXDOMAIN) if the name is not defined
    header.writeUInt16BE(addresses === undefined ? 0x8183 : 0x8180, 2);
    header.writeUInt16BE(1, 4); // QDCOUNT
    header.writeUInt16BE(answers.length, 6); // ANCOUNT
    return { response: Buffer.concat([header, query.subarray(12, end), ...answers]), name };
};

/**
 * Start a DNS server on 127.0.0.1 for testing.
 * It answers A and AAAA records defined in `records`.
 * `lookup` sends a real DNS query to the server, so the test does not depend on external DNS.
 */
export const startTestDnsServer = async (records: DnsRecords): Promise<TestDnsServer> => {
    const queriedHostnames: string[] = [];
    const socket = dgram.createSocket("udp4");
    socket.on("message", (query, remote) => {
        const { response, name } = createResponse(query, records);
        queriedHostnames.push(name);
        socket.send(response, remote.port, remote.address);
    });
    await new Promise<void>((resolve) => socket.bind(0, "127.0.0.1", resolve));
    const resolver = new dns.promises.Resolver({ timeout: 1000, tries: 1 });
    resolver.setServers([`127.0.0.1:${socket.address().port}`]);
    const resolve = (hostname: string, family: 4 | 6) => {
        const promise = family === 4 ? resolver.resolve4(hostname) : resolver.resolve6(hostname);
        return promise.then(
            (addresses) => addresses.map((address) => ({ address, family })),
            // no record
            () => []
        );
    };
    const lookup: LookupFunction = (hostname, options, callback) => {
        const families: (4 | 6)[] = options.family === 4 ? [4] : options.family === 6 ? [6] : [4, 6];
        Promise.all(families.map((family) => resolve(hostname, family))).then((results) => {
            const addresses = results.flat();
            if (addresses.length === 0) {
                const error: NodeJS.ErrnoException = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
                error.code = "ENOTFOUND";
                return callback(error, "", 4);
            }
            if (options.all) {
                return callback(null, addresses);
            }
            return callback(null, addresses[0].address, addresses[0].family);
        });
    };
    return {
        lookup,
        queriedHostnames,
        close: () => new Promise<void>((resolve) => socket.close(() => resolve()))
    };
};
