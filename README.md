# request-filtering-agent

A http(s).Agent implementation that filter request URLs by allow/deny list.

It help to prevent [server-side request forgery (SSRF)](https://en.wikipedia.org/wiki/Server-side_request_forgery) attack.
In other words, It prevent the request to private IP address/localhost.

- [What is SSRF (Server-side request forgery)? Tutorial & Examples](https://portswigger.net/web-security/ssrf)

## Install

Install with [npm](https://www.npmjs.com/):

    npm install request-filtering-agent

## Usage

`useAgent(url)` return an agent for the url.
`request-filtering-agent` disallow to request to [Private network](https://en.wikipedia.org/wiki/Private_network).

```js
const fetch = require("node-fetch");
const { useAgent } = require("request-filtering-agent");
const url = 'http://127.0.0.1.xip.io/';
fetch(url, {
    // use http or https agent for url
    agent: useAgent(url)
}).catch(err => {
    console.err(err); // DNS lookup 127.0.0.1(family:4, host:127.0.0.1.xip.io) is not allowed. Because, It is private IP address.
});
```

## API


```ts
export interface RequestFilteringAgentOptions {
    allowPrivateIP?: boolean;
    allowIPAddressList?: string[];
    denyIPAddressList?: string[];
}
export declare class RequestFilteringHttpAgent extends http.Agent {
    private requestFilterOptions;
    constructor(options?: http.AgentOptions & RequestFilteringAgentOptions);
    createConnection(options: TcpNetConnectOpts, connectionListener?: () => void): net.Socket;
}
export declare class RequestFilteringHttpsAgent extends https.Agent {
    private requestFilterOptions;
    constructor(options?: https.AgentOptions & RequestFilteringAgentOptions);
    createConnection(options: TcpNetConnectOpts, connectionListener?: () => void): net.Socket;
}
export declare const globalHttpAgent: RequestFilteringHttpAgent;
export declare const globalHttpsAgent: RequestFilteringHttpsAgent;
/**
 * get right an agent for the url
 * @param url
 */
export declare const useAgent: (url: string) => RequestFilteringHttpAgent | RequestFilteringHttpsAgent;
```

### Example: Create an Agent with options

```js
const fetch = require("node-fetch");
const { RequestFilteringHttpAgent } = require("request-filtering-agent");

// Create http agent that allow 127.0.0.1, but it disallow other private ip
const agent = new RequestFilteringHttpAgent({
    allowIPAddressList: ["127.0.0.1"], // it is preferred than allowPrivateIP option
    allowPrivateIP: false, // Default: false
});
// 127.0.0.1 is private ip address, but it is allowed
const url = 'http://127.0.0.1:8080/';
fetch(url, {
    agent: agent
}).then(res => {
    console.log(res); // OK
})
```

## Related

- [welefen/ssrf-agent: make http(s) request to prevent SSRF](https://github.com/welefen/ssrf-agent)

## Changelog

See [Releases page](https://github.com/azu/request-filtering-agent/releases).

## Running tests

Install devDependencies and Run `npm test`:

    npm test

## Contributing

Pull requests and stars are always welcome.

For bugs and feature requests, [please create an issue](https://github.com/azu/request-filtering-agent/issues).

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## Author

- [github/azu](https://github.com/azu)
- [twitter/azu_re](https://twitter.com/azu_re)

## License

MIT © azu
