# request.hpkp

[Request.js](https://www.npmjs.com/package/request) drop-in replacement with support for https public key pinning ([HPKP](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning)).

The module supports both public-key-pins and public-key-pins-report-only and implements report-uri callbacks.

## Installation

```
npm install request.hpkp --save
```

## Usage

```javascript
const request = require('request.hpkp');
request.get('https://domain.com', function(err,res,body){
    //this request will fail if HPKP check fails.
});
```
## How does it work
**"public-key-pins"** header is parsed and cached (for a TTL determined by the max-age parameter in this header) on the first sucessful https request to a host.

Subsequent calls to the same host are going to be checked against the cached keys.

### Key cache
The module will by default save keys for a hostname in a JSON file saved within the os.tmpdir().

The storage path can be overwritten by calling Request.hpkpCache

```javascript
const request = require('request.hpkp');
//set cache dir to /tmp/cacheDir (make sure the locatione exists!)

request.hpkpCache('/tmp/cacheDir');

request.get('https://domain.com', function(err,res,body){
    //this request will fail if HPKP check fails.
});
```

### Alternative key cache stores

You can use your own storage to cache and retrieve keys by overwritting set and get functions within the request.hpkpCache.

```javascript
const request = require('request.hpkp');

request.hpkpCache({
    get: function(hostname){
    },
    
    set: function(hostname, data){
    }
);

// the get function also needs to check data.expiresAt and delete when data is expired so that the pinned keys are refreshed as required.
```

## What's missing + need to know
* Somewhat hackish usage of request.js , need to refactor
* No automatic testing so far. Need to write some tests
* Report-uri doesn't send certificate only expected pins.


## Release History
* 0.0.2 Fixed issue with request.js helper functions parameters
* 0.0.1 Initial release