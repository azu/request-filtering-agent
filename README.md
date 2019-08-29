# request-filtering-agent [![Build Status](https://travis-ci.org/azu/request-filtering-agent.svg?branch=master)](https://travis-ci.org/azu/request-filtering-agent)

A http(s).Agent implementation that block request Private IP address.

It help to prevent [server-side request forgery (SSRF)](https://en.wikipedia.org/wiki/Server-side_request_forgery) attack.

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
const url = 'http://127.0.0.1:8080/';
fetch(url, {
    // use http or https agent for url
    agent: useAgent(url)
}).catch(err => {
    console.err(err); // DNS lookup 127.0.0.1(family:4, host:127.0.0.1.xip.io) is not allowed. Because, It is private IP address.
});
```

`request-filtering-agent` support loopback domain like [xip.io](http://xip.io) and [nip.io](https://nip.io/).
This library detect the IP adpress that is dns lookup-ed.


```
$ dig 127.0.0.1.xip.io

;127.0.0.1.xip.io.		IN	A

;; ANSWER SECTION:
127.0.0.1.xip.io.	300	IN	A	127.0.0.1
```

Example code:

```js
const fetch = require("node-fetch");
const { useAgent } = require("request-filtering-agent");
const url = 'http://127.0.0.1.xip.io:8080/';
fetch(url, {
    agent: useAgent(url)
}).catch(err => {
    console.err(err); // DNS lookup 127.0.0.1(family:4, host:127.0.0.1.xip.io) is not allowed. Because, It is private IP address.
});
```

It will prevent [DNS rebinding](https://en.wikipedia.org/wiki/DNS_rebinding)

## API


```ts
export interface RequestFilteringAgentOptions {
    allowPrivateIP?: boolean;
    allowIPAddressList?: string[];
    denyIPAddressList?: string[];
}
/**
 * Apply request filter to http(s).Agent instance
 */
export declare function applyRequestFilter<T extends http.Agent | http.Agent>(agent: T, options?: RequestFilteringAgentOptions): T;
/**
 * A subclsss of http.Agent with request filtering
 */
export declare class RequestFilteringHttpAgent extends http.Agent {
    constructor(options?: http.AgentOptions & RequestFilteringAgentOptions);
}
/**
 * A subclsss of https.Agent with request filtering
 */
export declare class RequestFilteringHttpsAgent extends https.Agent {
    constructor(options?: https.AgentOptions & RequestFilteringAgentOptions);
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

An agent that allow to request `127.0.0.1`, but it dissllow other Private IP.

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

### Example: Apply request filtering to exising `http.Agent`

You can apply request filtering to `http.Agent` or `https.Agent` using `applyRequestFilter` method.

```js
const http = require("http")
const fetch = require("node-fetch");
const { applyRequestFilter } = require("request-filtering-agent");

// Create http agent with keepAlive option
const agent = new http.Agent({
    keepAlive: true,
});
// Apply request filtering to http.Agent
const agentWithFiltering = applyRequestFilter(agent, {
    allowPrivateIP: false // Default: false
});
// 127.0.0.1 is private ip address
const url = 'http://127.0.0.1:8080/';
fetch(url, {
    agent: agentWithFiltering
}).catch(error => {
    console.error(error); // Dis-allowed
})
```

## `http.Agent` libraries

[http.Agent](https://nodejs.org/api/http.html#http_class_http_agent) is supported by popular library.

- [node-fetch](https://github.com/bitinn/node-fetch)
- [Request](https://github.com/request/request)
- [node-http-proxy](https://github.com/http-party/node-http-proxy)
- [axios](https://github.com/axios/axios)

`request-filtering-agent` work with these libraries.

## Related

- [welefen/ssrf-agent: make http(s) request to prevent SSRF](https://github.com/welefen/ssrf-agent)
    - It provide only high level wrapper

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
