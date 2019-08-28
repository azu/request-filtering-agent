import * as net from "net";
import { Socket, TcpNetConnectOpts } from "net";
import * as http from "http";
import * as https from "https";
import ip from "ip";

// Definition missing interface
declare module "http" {
    interface Agent {
        createConnection(options: TcpNetConnectOpts, connectionListener?: () => void): Socket;
    }
}

export interface RequestFilteringAgentOptions {
    // allow to connect private IP address
    // Default: false
    allowToConnectToPrivateIP?: boolean;
    // Allow address list
    // This values are preferred than denyAddressList
    // Default: []
    allowIPAddressList?: string[];
    // Deny address list
    // Default: []
    denyIPAddressList?: string[]
}

const addDropFilterSocket = (options: RequestFilteringAgentOptions, socket: net.Socket) => {
    socket.addListener("lookup", (err, address, family, host) => {
        if (err) {
            return;
        }
        if (!options.allowToConnectToPrivateIP) {
            if (ip.isPrivate(address)) {
                return socket.destroy(new Error(`DNS lookup ${address}(family:${family}, host:${host}) is not allowed. Because, It is private IP address.`));
            }
        }

        if (options.allowIPAddressList && options.allowIPAddressList.includes(address)) {
            return;
        }

        if (options.denyIPAddressList &&options.denyIPAddressList.includes(address)) {
            return socket.destroy(new Error(`DNS lookup ${address}(family:${family}, host:${host}) is not allowed. Because It is defined in denyAddressList.`));
        }
        return;
    });
};

export class RequestFilteringHttpAgent extends http.Agent {
    private requestFilterOptions: RequestFilteringAgentOptions;

    constructor(options?: http.AgentOptions & RequestFilteringAgentOptions) {
        super(options);
        this.requestFilterOptions = {
            allowToConnectToPrivateIP: options && options.allowToConnectToPrivateIP !== undefined ? options.allowToConnectToPrivateIP : false,
            allowIPAddressList: options && options.allowIPAddressList ? options.allowIPAddressList : [],
            denyIPAddressList: options && options.denyIPAddressList ? options.denyIPAddressList : []
        };
    }

    // override http.Agent#createConnection
    // https://nodejs.org/api/http.html#http_agent_createconnection_options_callback
    // https://nodejs.org/api/net.html#net_net_createconnection_options_connectlistener
    createConnection(options: TcpNetConnectOpts, connectionListener?: () => void): net.Socket {
        const netSockets: net.Socket = super.createConnection(options, connectionListener);
        addDropFilterSocket(this.requestFilterOptions, netSockets);
        return netSockets;
    }
}

export class RequestFilteringHttpsAgent extends https.Agent {
    private requestFilterOptions: RequestFilteringAgentOptions;

    constructor(options?: https.AgentOptions & RequestFilteringAgentOptions) {
        super(options);
        this.requestFilterOptions = {
            allowToConnectToPrivateIP: options && options.allowToConnectToPrivateIP !== undefined ? options.allowToConnectToPrivateIP : false,
            allowIPAddressList: options && options.allowIPAddressList ? options.allowIPAddressList : [],
            denyIPAddressList: options && options.denyIPAddressList ? options.denyIPAddressList : []
        };
    }

    // override https.Agent#createConnection
    // https://nodejs.org/api/http.html#http_agent_createconnection_options_callback
    // https://nodejs.org/api/net.html#net_net_createconnection_options_connectlistener
    createConnection(options: TcpNetConnectOpts, connectionListener?: () => void): net.Socket {
        const socket: net.Socket = super.createConnection(options, connectionListener);
        addDropFilterSocket(this.requestFilterOptions, socket);
        return socket;
    }
}
