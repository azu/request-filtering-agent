import * as assert from "assert";
import fetch from "node-fetch";
import { URL } from "url";
import { RequestFilteringHttpAgent, RequestFilteringHttpsAgent } from "../src/request-filtering-agent";

describe("request-filtering-agent", function() {
    it("should not request local ip address", async () => {
        const privateIPs = [
            "http://127.0.0.1",
            "http://017700000001",
            "http://A.com@127.0.0.1",
            "http://tino.local",
            "http://127.0.0.1.xip.io/",
            "https://127.0.0.1.xip.io/",
            "http://localhost",
            // aws
            "http://169.254.169.254/latest/user-data",
            // gcp
            "http://169.254.169.254/computeMetadata/v1/"
        ];
        for (const ipAddress of privateIPs) {
            const agent = (new URL(ipAddress)).protocol === "http:"
                ? new RequestFilteringHttpAgent()
                : new RequestFilteringHttpsAgent();
            try {
                await fetch(ipAddress, {
                    agent,
                    timeout: 1000
                });
                throw new ReferenceError("should not be called");
            } catch (error) {
                if (error instanceof ReferenceError) {
                    assert.fail(error);
                }
            }
        }
    });
    it("should not request local ip address", async () => {
        const agent = new RequestFilteringHttpAgent({
            denyIPAddressList: ["example.com"]
        });
        try {
            await fetch("http://example.com", {
                agent
            });
            throw new ReferenceError("should not be called");
        } catch (error) {
            if (error instanceof ReferenceError) {
                assert.fail(error);
            }
            console.log(error);
        }
    });
});
