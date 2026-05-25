// Minimal stub for 22_http_client.js - we removed Deno.createHttpClient()
// but 23_request.js still references HttpClientPrototype for type-checking.
(function () {
var HttpClientPrototype = {};
return { HttpClientPrototype };
})();
