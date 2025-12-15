import * as net from "node:net";
import type { TcpNetConnectOpts } from "node:net";
import * as http from "node:http";
import * as https from "node:https";
import ipaddr from "ipaddr.js";
import * as dns from "node:dns";
import type { Duplex } from "node:stream";

export interface RequestFilteringAgentOptions {
    // Allow to connect private IP address if allowPrivateIPAddress is true
    // This includes Private IP addresses and Reserved IP addresses.
    // https://en.wikipedia.org/wiki/Private_network
    // https://en.wikipedia.org/wiki/Reserved_IP_addresses
    // Example, http://127.0.0.1/, http://localhost/, https://169.254.169.254/
    // Default: false
    allowPrivateIPAddress?: boolean;
    // Allow to connect meta address 0.0.0.0 if allowPrivateIPAddress is true
    // 0.0.0.0 (IPv4) and :: (IPv6) a meta/unspecified address that routing another address
    // https://en.wikipedia.org/wiki/Reserved_IP_addresses
    // https://tools.ietf.org/html/rfc6890
    // Default: false
    allowMetaIPAddress?: boolean;
    // Allow address list
    // These values are preferred than denyAddressList
    // Default: []
    allowIPAddressList?: string[];
    // Deny address list
    // Default: []
    denyIPAddressList?: string[];
}

export const DefaultRequestFilteringAgentOptions: Required<RequestFilteringAgentOptions> = {
    allowPrivateIPAddress: false,
    allowMetaIPAddress: false,
    allowIPAddressList: [],
    denyIPAddressList: []
};

/**
 * Check if an IP address matches an IP or CIDR in the list
 * @param address IP address string
 * @param addr Parsed IP address object
 * @param ipList List of IPs or CIDRs
 * @param listName Name of the list (for warning messages)
 * @returns true if the address matches any IP or CIDR in the list
 */
const matchIPAddress = (
    address: string,
    addr: ipaddr.IPv4 | ipaddr.IPv6,
    ipList: string[],
    listName: string
): boolean => {
    for (const ipOrCIDR of ipList) {
        // if ipOrCIDR is a single IP address
        if (net.isIP(ipOrCIDR) !== 0) {
            if (ipOrCIDR === address) {
                return true;
            }
        } else {
            // if ipOrCIDR is a CIDR
            try {
                const cidr = ipaddr.parseCIDR(ipOrCIDR);
                if (addr.match(cidr)) {
                    return true;
                }
            } catch (e) {
                // not a valid CIDR, show warning
                // TODO: Throw an exception in a future major update instead of just warning
                // This is a programming error and should be treated as such
                console.warn(
                    new Error(`[request-filtering-agent] Invalid CIDR in ${listName}: ${ipOrCIDR}`, { cause: e })
                );
            }
        }
    }
    return false;
};

/**
 * validate the address that is matched the validation options
 * @param address ip address
 * @param host optional
 * @param family optional
 * @param options
 */
const validateIPAddress = (
    { address, host, family }: { address: string; host?: string; family?: string | number },
    options: Required<RequestFilteringAgentOptions>
): undefined | Error => {
    // if it is not IP address, skip it
    if (net.isIP(address) === 0) {
        return;
    }
    try {
        const addr = ipaddr.parse(address);
        // prefer allowed list
        if (options.allowIPAddressList.length > 0) {
            if (matchIPAddress(address, addr, options.allowIPAddressList, "allowIPAddressList")) {
                return; // It is allowed
            }
        }
        const range = addr.range();
        if (!options.allowMetaIPAddress) {
            // address === "0.0.0.0" || address == "::"
            if (range === "unspecified") {
                return new Error(
                    `DNS lookup ${address}(family:${family}, host:${host}) is not allowed. Because, It is meta IP address.`
                );
            }
        }
        // TODO: rename option name
        if (!options.allowPrivateIPAddress && range !== "unicast") {
            return new Error(
                `DNS lookup ${address}(family:${family}, host:${host}) is not allowed. Because, It is private IP address.`
            );
        }

        if (options.denyIPAddressList.length > 0) {
            if (matchIPAddress(address, addr, options.denyIPAddressList, "denyIPAddressList")) {
                return new Error(
                    `DNS lookup ${address}(family:${family}, host:${host}) is not allowed. Because It is defined in denyIPAddressList.`
                );
            }
        }
    } catch (error) {
        return error as Error; // if can not parse IP address, throw error
    }
    return;
};

// @types/node has a poor definition of this callback (uses "addresses" version if option.all = true)
type LookupOneCallback = (err: NodeJS.ErrnoException | null, address?: string, family?: number) => void;
type LookupAllCallback = (err: NodeJS.ErrnoException | null, addresses?: dns.LookupAddress[]) => void;
type LookupCallback = LookupOneCallback | LookupAllCallback;

const makeLookup = (
    createConnectionOptions: TcpNetConnectOpts,
    requestFilterOptions: Required<RequestFilteringAgentOptions>
): Required<net.TcpSocketConnectOpts>["lookup"] => {
    // @ts-expect-error - @types/node has a poor definition of this callback
    return (hostname, options, cb: LookupCallback) => {
        const lookup = createConnectionOptions.lookup || dns.lookup;
        let lookupCb: LookupCallback;
        if (options.all) {
            lookupCb = ((err, addresses) => {
                if (err) {
                    cb(err);
                    return;
                }
                for (const { address, family } of addresses!) {
                    const validationError = validateIPAddress(
                        { address, family, host: hostname },
                        requestFilterOptions
                    );
                    if (validationError) {
                        cb(validationError);
                        return;
                    }
                }
                (cb as LookupAllCallback)(null, addresses);
            }) as LookupAllCallback;
        } else {
            lookupCb = ((err, address, family) => {
                if (err) {
                    cb(err);
                    return;
                }
                const validationError = validateIPAddress(
                    { address: address!, family: family!, host: hostname },
                    requestFilterOptions
                );
                if (validationError) {
                    cb(validationError);
                    return;
                }
                (cb as LookupOneCallback)(null, address!, family!);
            }) as LookupOneCallback;
        }
        // @ts-expect-error - @types/node has a poor definition of this callback
        lookup(hostname, options, lookupCb);
    };
};

/**
 * A subclass of http.Agent with request filtering
 */
export class RequestFilteringHttpAgent extends http.Agent {
    private requestFilterOptions: Required<RequestFilteringAgentOptions>;

    constructor(options?: http.AgentOptions & RequestFilteringAgentOptions) {
        super(options);
        this.requestFilterOptions = {
            allowPrivateIPAddress:
                options && options.allowPrivateIPAddress !== undefined
                    ? options.allowPrivateIPAddress
                    : DefaultRequestFilteringAgentOptions.allowPrivateIPAddress,
            allowMetaIPAddress:
                options && options.allowMetaIPAddress !== undefined
                    ? options.allowMetaIPAddress
                    : DefaultRequestFilteringAgentOptions.allowMetaIPAddress,
            allowIPAddressList:
                options && options.allowIPAddressList
                    ? options.allowIPAddressList
                    : DefaultRequestFilteringAgentOptions.allowIPAddressList,
            denyIPAddressList:
                options && options.denyIPAddressList
                    ? options.denyIPAddressList
                    : DefaultRequestFilteringAgentOptions.denyIPAddressList
        };
    }

    // override http.Agent#createConnection
    // https://nodejs.org/api/http.html#http_agent_createconnection_options_callback
    // https://nodejs.org/api/net.html#net_net_createconnection_options_connectlistener
    createConnection(options: TcpNetConnectOpts, connectionListener?: (error: Error | null, socket: Duplex) => void) {
        const { host } = options;
        if (host !== undefined) {
            // Direct ip address request without dns-lookup
            // Example: http://127.0.0.1
            // https://nodejs.org/api/net.html#net_socket_connect_options_connectlistener
            const validationError = validateIPAddress({ address: host }, this.requestFilterOptions);
            if (validationError) {
                throw validationError;
            }
        }
        // https://nodejs.org/api/net.html#net_socket_connect_options_connectlistener
        return super.createConnection(
            { ...options, lookup: makeLookup(options, this.requestFilterOptions) },
            connectionListener
        );
    }
}

/**
 * A subclass of https.Agent with request filtering
 */
export class RequestFilteringHttpsAgent extends https.Agent {
    private requestFilterOptions: Required<RequestFilteringAgentOptions>;

    constructor(options?: https.AgentOptions & RequestFilteringAgentOptions) {
        super(options);
        this.requestFilterOptions = {
            allowPrivateIPAddress:
                options && options.allowPrivateIPAddress !== undefined ? options.allowPrivateIPAddress : false,
            allowMetaIPAddress:
                options && options.allowMetaIPAddress !== undefined ? options.allowMetaIPAddress : false,
            allowIPAddressList: options && options.allowIPAddressList ? options.allowIPAddressList : [],
            denyIPAddressList: options && options.denyIPAddressList ? options.denyIPAddressList : []
        };
    }

    // override http.Agent#createConnection
    // https://nodejs.org/api/http.html#http_agent_createconnection_options_callback
    // https://nodejs.org/api/net.html#net_net_createconnection_options_connectlistener
    createConnection(options: TcpNetConnectOpts, connectionListener?: (error: Error | null, socket: Duplex) => void) {
        const { host } = options;
        if (host !== undefined) {
            // Direct ip address request without dns-lookup
            // Example: http://127.0.0.1
            // https://nodejs.org/api/net.html#net_socket_connect_options_connectlistener
            const validationError = validateIPAddress({ address: host }, this.requestFilterOptions);
            if (validationError) {
                throw validationError;
            }
        }
        // https://nodejs.org/api/net.html#net_socket_connect_options_connectlistener
        return super.createConnection(
            { ...options, lookup: makeLookup(options, this.requestFilterOptions) },
            connectionListener
        );
    }
}

export const globalHttpAgent = new RequestFilteringHttpAgent();
export const globalHttpsAgent = new RequestFilteringHttpsAgent();
/**
 * Get an agent for the url
 * return http or https agent
 * @param url
 * @param options
 */
export const useAgent = (url: string, options?: https.AgentOptions & RequestFilteringAgentOptions) => {
    if (!options) {
        return url.startsWith("https") ? globalHttpsAgent : globalHttpAgent;
    }
    return url.startsWith("https") ? new RequestFilteringHttpsAgent(options) : new RequestFilteringHttpAgent(options);
};
