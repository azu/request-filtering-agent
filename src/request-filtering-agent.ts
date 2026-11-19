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
    /**
     * @deprecated Use `filter` option instead. It will be removed in a future major version.
     */
    allowIPAddressList?: string[];
    // Deny address list
    // Default: []
    /**
     * @deprecated Use `filter` option instead. It will be removed in a future major version.
     */
    denyIPAddressList?: string[];
    // Custom filter function that is called with the resolved and normalized IP address
    // It is called after the built-in checks (allowPrivateIPAddress, allowMetaIPAddress, denyIPAddressList) pass.
    // It is also called for the address that is allowed by allowIPAddressList.
    // Only a strict `true` return value allows the connection.
    // It is called when a new connection is created. It is not called for a request that reuses a keep-alive connection.
    // If DNS lookup returns multiple IP addresses, the request is blocked if filter rejects any of them.
    // Default: undefined (no custom filter)
    filter?: RequestFilteringAgentFilter;
}

export interface RequestFilteringAgentFilterContext {
    /**
     * The original IP address before normalization.
     * It is the value returned by DNS lookup or the literal IP address in the URL.
     * Example: "::ffff:127.0.0.1"
     */
    raw: string;
    /**
     * IP family of the normalized address: 4 or 6
     */
    family: 4 | 6;
    /**
     * The hostname that is requested.
     * It is undefined when the request uses a literal IP address.
     */
    host?: string;
    /**
     * The range name of the normalized address defined by ipaddr.js.
     * It is the same range that the built-in checks use:
     * "unicast" is a public address, and an IPv6 address outside of 2000::/3 is "reserved" instead of "unicast".
     * Example: "unicast", "private", "loopback", "linkLocal", "unspecified", "reserved"
     * https://github.com/whitequark/ipaddr.js/blob/main/lib/ipaddr.js
     */
    range: string;
}

/**
 * Custom filter function.
 * @param address The normalized IP address after DNS resolution.
 *   IPv4-mapped IPv6 addresses are converted to IPv4 (e.g. "::ffff:127.0.0.1" → "127.0.0.1"),
 *   and IPv6 addresses are converted to the compact form (e.g. "0:0:0:0:0:0:0:1" → "::1").
 * @param context The context that includes the raw address before normalization.
 * @returns `true` to allow the connection. Any other value blocks the connection.
 */
export type RequestFilteringAgentFilter = (address: string, context: RequestFilteringAgentFilterContext) => boolean;

type ResolvedRequestFilteringAgentOptions = Required<Omit<RequestFilteringAgentOptions, "filter">> &
    Pick<RequestFilteringAgentOptions, "filter">;

export const DefaultRequestFilteringAgentOptions: ResolvedRequestFilteringAgentOptions = {
    allowPrivateIPAddress: false,
    allowMetaIPAddress: false,
    allowIPAddressList: [],
    denyIPAddressList: [],
    filter: undefined
};

const resolveOptions = (options?: RequestFilteringAgentOptions): ResolvedRequestFilteringAgentOptions => {
    return {
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
                : DefaultRequestFilteringAgentOptions.denyIPAddressList,
        filter: options && options.filter ? options.filter : DefaultRequestFilteringAgentOptions.filter
    };
};

/**
 * Check if an IP address matches an IP or CIDR in the list
 * @param params.targetAddress Target IP address to check (both string and parsed forms)
 * @param params.ipAddressList List of IPs or CIDRs to match against (allowIPAddressList or denyIPAddressList)
 * @param params.listName Name of the list (for warning messages)
 * @returns true if the target address matches any IP or CIDR in the list
 */
const matchIPAddress = ({
    targetAddress,
    ipAddressList,
    listName
}: {
    targetAddress: {
        raw: string;
        parsed: ipaddr.IPv4 | ipaddr.IPv6;
    };
    ipAddressList: string[];
    listName: string;
}): boolean => {
    for (const ipOrCIDR of ipAddressList) {
        // if ipOrCIDR is a single IP address
        if (net.isIP(ipOrCIDR) !== 0) {
            if (ipOrCIDR === targetAddress.raw) {
                return true;
            }
        } else {
            // if ipOrCIDR is a CIDR
            try {
                const cidr = ipaddr.parseCIDR(ipOrCIDR);
                // A CIDR of the other address family can never match the target.
                // ipaddr's match() throws for it, which is not an invalid CIDR.
                if (cidr[0].kind() !== targetAddress.parsed.kind()) {
                    continue;
                }
                if (targetAddress.parsed.match(cidr)) {
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

// IANA allocates only 2000::/3 as IPv6 Global Unicast. Everything else is reserved by IETF or special-purpose.
// https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
// ipaddr.js returns "unicast" for any address that is not in its special ranges list,
// so deprecated or unassigned ranges such as IPv4-compatible IPv6 addresses (::/96) are treated as "unicast".
// Treat an IPv6 address as "unicast" only if it is in 2000::/3.
const IPV6_GLOBAL_UNICAST_RANGE = ipaddr.parseCIDR("2000::/3");
const getRange = (parsedAddr: ipaddr.IPv4 | ipaddr.IPv6): string => {
    const range = parsedAddr.range();
    if (range === "unicast" && parsedAddr.kind() === "ipv6" && !parsedAddr.match(IPV6_GLOBAL_UNICAST_RANGE)) {
        return "reserved";
    }
    return range;
};

// ipaddr.js parses the deprecated notation "::a.b.c.d" as an IPv4-mapped IPv6 address (::ffff:a.b.c.d).
// However, OS treats it as an IPv4-compatible IPv6 address (::/96), and the request connects to ::/96.
// DNS lookup also returns this notation. For example, getaddrinfo returns "::8.8.8.8" for ::808:808.
// Rewrite it to the notation that ipaddr.js parses in the same way as OS.
// Example: "::8.8.8.8" → "0:0:0:0:0:0:8.8.8.8" (= ::808:808)
const IPV4_COMPATIBLE_DOTTED_NOTATION = /^::(?=\d+\.\d+\.\d+\.\d+(?:%.*)?$)/;
const toParsableAddress = (address: string): string => {
    return address.replace(IPV4_COMPATIBLE_DOTTED_NOTATION, "0:0:0:0:0:0:");
};

/**
 * Apply the custom filter function to the address
 * It returns an error if filter does not return strict `true`
 */
const applyFilter = (
    { address, host, family }: { address: string; host?: string; family?: string | number },
    options: ResolvedRequestFilteringAgentOptions
): undefined | Error => {
    if (!options.filter) {
        return;
    }
    // ipaddr.process converts IPv4-mapped IPv6 address to IPv4 address
    const normalizedAddr = ipaddr.process(toParsableAddress(address));
    let allowed: unknown;
    try {
        allowed = options.filter(normalizedAddr.toString(), {
            raw: address,
            family: normalizedAddr.kind() === "ipv4" ? 4 : 6,
            host,
            // Use the same range as the built-in checks. IPv6 address outside of 2000::/3 is not "unicast"
            range: getRange(normalizedAddr)
        });
    } catch (error) {
        // filter can throw any value such as `undefined` or `null`.
        // Always return an Error to block the connection, because a falsy value is treated as "no error".
        if (error instanceof Error) {
            return error;
        }
        return new Error(
            `DNS lookup ${address}(family:${family}, host:${host}) is not allowed. Because filter throws a non-Error value.`,
            { cause: error }
        );
    }
    if (allowed !== true) {
        return new Error(
            `DNS lookup ${address}(family:${family}, host:${host}) is not allowed. Because It is rejected by filter.`
        );
    }
    return;
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
    options: ResolvedRequestFilteringAgentOptions
): undefined | Error => {
    // if it is not IP address, skip it
    if (net.isIP(address) === 0) {
        return;
    }
    try {
        const parsedAddr = ipaddr.parse(toParsableAddress(address));
        // prefer allowed list
        if (options.allowIPAddressList.length > 0) {
            if (
                matchIPAddress({
                    targetAddress: {
                        raw: address,
                        parsed: parsedAddr
                    },
                    ipAddressList: options.allowIPAddressList,
                    listName: "allowIPAddressList"
                })
            ) {
                // It is allowed by allowIPAddressList, but filter is still applied
                return applyFilter({ address, host, family }, options);
            }
        }
        const range = getRange(parsedAddr);
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
            if (
                matchIPAddress({
                    targetAddress: {
                        raw: address,
                        parsed: parsedAddr
                    },
                    ipAddressList: options.denyIPAddressList,
                    listName: "denyIPAddressList"
                })
            ) {
                return new Error(
                    `DNS lookup ${address}(family:${family}, host:${host}) is not allowed. Because It is defined in denyIPAddressList.`
                );
            }
        }

        return applyFilter({ address, host, family }, options);
    } catch (error) {
        return error as Error; // if can not parse IP address, throw error
    }
};

// @types/node has a poor definition of this callback (uses "addresses" version if option.all = true)
type LookupOneCallback = (err: NodeJS.ErrnoException | null, address?: string, family?: number) => void;
type LookupAllCallback = (err: NodeJS.ErrnoException | null, addresses?: dns.LookupAddress[]) => void;
type LookupCallback = LookupOneCallback | LookupAllCallback;

const makeLookup = (
    createConnectionOptions: TcpNetConnectOpts,
    requestFilterOptions: ResolvedRequestFilteringAgentOptions
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

const createConnectionErrorSocket = (
    error: Error,
    connectionListener?: (error: Error | null, socket: Duplex) => void
): net.Socket => {
    const socket = new net.Socket();
    if (connectionListener) {
        connectionListener(error, socket);
    } else {
        socket.destroy(error);
    }
    return socket;
};

/**
 * A subclass of http.Agent with request filtering
 */
export class RequestFilteringHttpAgent extends http.Agent {
    private requestFilterOptions: ResolvedRequestFilteringAgentOptions;

    constructor(options?: http.AgentOptions & RequestFilteringAgentOptions) {
        super(options);
        this.requestFilterOptions = resolveOptions(options);
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
                return createConnectionErrorSocket(validationError, connectionListener);
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
    private requestFilterOptions: ResolvedRequestFilteringAgentOptions;

    constructor(options?: https.AgentOptions & RequestFilteringAgentOptions) {
        super(options);
        this.requestFilterOptions = resolveOptions(options);
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
                return createConnectionErrorSocket(validationError, connectionListener);
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
