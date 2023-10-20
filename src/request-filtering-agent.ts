import * as net from "net";
import { TcpNetConnectOpts } from "net";
import * as http from "http";
import * as https from "https";
import ipaddr from "ipaddr.js";
import { Socket } from "net";

export interface RequestFilteringAgentOptions {
    // Allow to connect private IP address
    // This includes Private IP addresses and Reserved IP addresses.
    // https://en.wikipedia.org/wiki/Private_network
    // https://en.wikipedia.org/wiki/Reserved_IP_addresses
    // Example, http://127.0.0.1/, http://localhost/, https://169.254.169.254/
    // Default: false
    allowPrivateIPAddress?: boolean;
    // Allow to connect meta address 0.0.0.0
    // 0.0.0.0 (IPv4) and :: (IPv6) a meta address that routing another address
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
    // prevent url redirection attack
    // connection not made to private IP adresses where the port is closed
    // Default: false
    stopPortScanningByUrlRedirection?: boolean;
}

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
): null | undefined | Error => {
    // if it is not IP address, skip it
    if (net.isIP(address) === 0) {
        return;
    }
    try {
        const addr = ipaddr.parse(address);
        const range = addr.range();
        // prefer allowed list
        if (options.allowIPAddressList.length > 0 && options.allowIPAddressList.includes(address)) {
            return;
        }
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

        if (options.denyIPAddressList.length > 0 && options.denyIPAddressList.includes(address)) {
            return new Error(
                `DNS lookup ${address}(family:${family}, host:${host}) is not allowed. Because It is defined in denyIPAddressList.`
            );
        }
    } catch (error) {
        return error as Error; // if can not parse IP address, throw error
    }
    return;
};

// dns lookup -> check
const addDropFilterSocket = (options: Required<RequestFilteringAgentOptions>, socket: net.Socket) => {
    socket.addListener("lookup", (err, address, family, host) => {
        if (err) {
            return;
        }
        const error = validateIPAddress({ address, family, host }, options);
        if (error) {
            socket.destroy(error);
        }
    });
};

// public
// prevent twice apply
const appliedAgentSet = new WeakSet<http.Agent | https.Agent>();

/**
 * Apply request filter to http(s).Agent instance
 */
export function applyRequestFilter<T extends http.Agent | https.Agent>(
    agent: T,
    options?: RequestFilteringAgentOptions
): T {
    if (appliedAgentSet.has(agent)) {
        return agent;
    }
    appliedAgentSet.add(agent);
    const requestFilterOptions: Required<RequestFilteringAgentOptions> = {
        allowPrivateIPAddress:
            options && options.allowPrivateIPAddress !== undefined ? options.allowPrivateIPAddress : false,
        allowMetaIPAddress: options && options.allowMetaIPAddress !== undefined ? options.allowMetaIPAddress : false,
        allowIPAddressList: options && options.allowIPAddressList ? options.allowIPAddressList : [],
        denyIPAddressList: options && options.denyIPAddressList ? options.denyIPAddressList : [],
        stopPortScanningByUrlRedirection:
            options && options.stopPortScanningByUrlRedirection !== undefined
                ? options.stopPortScanningByUrlRedirection
                : false
    };
    // override http.Agent#createConnection
    // https://nodejs.org/api/http.html#http_agent_createconnection_options_callback
    // https://nodejs.org/api/net.html#net_net_createconnection_options_connectlistener
    // @ts-expect-error - @types/node does not defined createConnection
    const createConnection = agent.createConnection;
    // @ts-expect-error - @types/node does not defined createConnection
    agent.createConnection = (options: TcpNetConnectOpts, connectionListener?: (error?: Error) => void) => {
        if (requestFilterOptions.stopPortScanningByUrlRedirection) {
            // Prevents malicious user from identifying which ports are open
            const { host, family } = options;
            if (host && net.isIP(host)) {
                const addr = ipaddr.parse(host);
                const range = addr.range();
                if (range !== "unicast") {
                    throw new Error(
                        `DNS lookup ${host}(family:${family}, host:${host}) is not allowed. Because, It is private IP address.`
                    );
                }
            }
        }

        const socket = createConnection.call(agent, options, () => {
            // https://nodejs.org/api/net.html#net_socket_connect_options_connectlistener
            const { host } = options;
            if (host) {
                // Direct ip address request without dns-lookup
                // Example: http://127.0.0.1
                // https://nodejs.org/api/net.html#net_socket_connect_options_connectlistener
                const error = validateIPAddress({ address: host }, requestFilterOptions);
                if (error) {
                    socket.destroy(error);
                }
            }
            if (typeof connectionListener === "function") {
                connectionListener();
            }
        });
        // Request with domain name
        // Example: http://127.0.0.1.nip.io/
        addDropFilterSocket(requestFilterOptions, socket);
        return socket;
    };
    return agent;
}

/**
 * A subclass of http.Agent with request filtering
 */
export class RequestFilteringHttpAgent extends http.Agent {
    private requestFilterOptions: Required<RequestFilteringAgentOptions>;

    constructor(options?: http.AgentOptions & RequestFilteringAgentOptions) {
        super(options);
        this.requestFilterOptions = {
            allowPrivateIPAddress:
                options && options.allowPrivateIPAddress !== undefined ? options.allowPrivateIPAddress : false,
            allowMetaIPAddress:
                options && options.allowMetaIPAddress !== undefined ? options.allowMetaIPAddress : false,
            allowIPAddressList: options && options.allowIPAddressList ? options.allowIPAddressList : [],
            denyIPAddressList: options && options.denyIPAddressList ? options.denyIPAddressList : [],
            stopPortScanningByUrlRedirection:
                options && options.stopPortScanningByUrlRedirection !== undefined
                    ? options.stopPortScanningByUrlRedirection
                    : false
        };
    }

    createConnection(options: TcpNetConnectOpts, connectionListener?: (error: Error | null, socket: Socket) => void) {
        console.log("createConnectio !!!!n");
        let validationError: Error | null | undefined = null;
        if (this.requestFilterOptions.stopPortScanningByUrlRedirection) {
            // Prevents malicious user from identifying which ports are open
            const { host, family } = options;
            if (host && net.isIP(host)) {
                const addr = ipaddr.parse(host);
                const range = addr.range();
                if (range !== "unicast") {
                    throw new Error(
                        `DNS lookup ${host}(family:${family}, host:${host}) is not allowed. Because, It is private IP address.`
                    );
                }
            }
        }
        // console.log("createConnection", options);
        const { host } = options;
        if (host) {
            // Direct ip address request without dns-lookup
            // Example: http://127.0.0.1
            // https://nodejs.org/api/net.html#net_socket_connect_options_connectlistener
            validationError = validateIPAddress({ address: host }, this.requestFilterOptions);
        }
        // https://nodejs.org/api/net.html#net_socket_connect_options_connectlistener
        let isSocketEnding = false;
        // @ts-expect-error - @types/node does not defined createConnection
        const socket: Socket = super.createConnection(options, connectionListener);
        const onReady = () => {
            if (validationError) {
                if (isSocketEnding) {
                    return;
                }
                if (socket.destroyed) {
                    return;
                }
                isSocketEnding = true;
                socket.removeListener("ready", onReady);
                socket.end(() => {
                    console.log("end 1");
                    if (validationError) {
                        if (socket.destroyed) {
                            return;
                        }
                        socket.destroy(validationError);
                    }
                });
            }
        };
        socket.addListener("ready", onReady);
        // Request with domain name
        // Example: http://127.0.0.1.nip.io/
        const weakSet = new WeakSet<Socket>();
        const onLookup = (err: Error, address: string, family: string | number, host: string): void => {
            if (err) {
                return;
            }
            console.log({
                family,
                host
            });
            const error = validateIPAddress({ address, family, host }, this.requestFilterOptions);
            console.log("validation 2 ", error);
            if (error) {
                if (weakSet.has(socket)) {
                    return;
                }
                weakSet.add(socket);
                socket.removeListener("lookup", onLookup);
                if (socket.destroyed) {
                    return;
                }
                socket.end(() => {
                    console.log("end 2");
                    if (socket.destroyed) {
                        return;
                    }
                    console.log("end 3 ", socket.destroyed);
                    console.log("end errr", validationError?.message);
                    socket.destroy(error);
                });
            }
        };
        socket.addListener("lookup", onLookup);
        return socket;
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
            denyIPAddressList: options && options.denyIPAddressList ? options.denyIPAddressList : [],
            stopPortScanningByUrlRedirection:
                options && options.stopPortScanningByUrlRedirection !== undefined
                    ? options.stopPortScanningByUrlRedirection
                    : false
        };
    }

    createConnection(options: TcpNetConnectOpts, connectionListener?: (error: Error | null, socket: Socket) => void) {
        console.log("createConnectio !!!!n");
        let validationError: Error | null | undefined = null;
        if (this.requestFilterOptions.stopPortScanningByUrlRedirection) {
            // Prevents malicious user from identifying which ports are open
            const { host, family } = options;
            if (host && net.isIP(host)) {
                const addr = ipaddr.parse(host);
                const range = addr.range();
                if (range !== "unicast") {
                    throw new Error(
                        `DNS lookup ${host}(family:${family}, host:${host}) is not allowed. Because, It is private IP address.`
                    );
                }
            }
        }
        // console.log("createConnection", options);
        const { host } = options;
        if (host) {
            // Direct ip address request without dns-lookup
            // Example: http://127.0.0.1
            // https://nodejs.org/api/net.html#net_socket_connect_options_connectlistener
            validationError = validateIPAddress({ address: host }, this.requestFilterOptions);
        }
        // https://nodejs.org/api/net.html#net_socket_connect_options_connectlistener
        let isSocketEnding = false;
        // @ts-expect-error - @types/node does not defined createConnection
        const socket: Socket = super.createConnection(options, connectionListener);
        const onReady = () => {
            if (validationError) {
                if (isSocketEnding) {
                    return;
                }
                if (socket.destroyed) {
                    return;
                }
                isSocketEnding = true;
                socket.removeListener("ready", onReady);
                socket.end(() => {
                    console.log("end 1");
                    if (validationError) {
                        if (socket.destroyed) {
                            return;
                        }
                        socket.destroy(validationError);
                    }
                });
            }
        };
        socket.addListener("ready", onReady);
        // Request with domain name
        // Example: http://127.0.0.1.nip.io/
        let isEndong: boolean = false;
        const weakSet = new WeakSet<Socket>();
        const onLookup = (err: Error, address: string, family: string | number, host: string): void => {
            if (err) {
                return;
            }
            const error = validateIPAddress({ address, family, host }, this.requestFilterOptions);
            console.log("validation 2 ", error);
            if (error) {
                if (weakSet.has(socket)) {
                    return;
                }
                if (isEndong) {
                    return;
                }
                weakSet.add(socket);
                isEndong = true;
                socket.removeListener("lookup", onLookup);
                if (socket.destroyed) {
                    return;
                }
                socket.end(() => {
                    console.log("end 2");
                    if (socket.destroyed) {
                        return;
                    }
                    console.log("end 3 ", socket.destroyed);
                    console.log("end errr", validationError?.message);
                    socket.destroy(error);
                });
            }
        };
        socket.addListener("lookup", onLookup);
        return socket;
    }
}

export const globalHttpAgent = new RequestFilteringHttpAgent();
export const globalHttpsAgent = new RequestFilteringHttpsAgent();
/**
 * Get an agent for the url
 * return http or https agent
 * @param url
 */
export const useAgent = (url: string, options?: https.AgentOptions & RequestFilteringAgentOptions) => {
    if (!options) {
        return url.startsWith("https") ? globalHttpsAgent : globalHttpAgent;
    }
    return url.startsWith("https") ? new RequestFilteringHttpsAgent(options) : new RequestFilteringHttpAgent(options);
};
