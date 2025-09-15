# `comments.hanyuone.live`

A blog comment system for my website, `hanyuone.live`. It is designed to be hosted on
CloudFlare Workers, and linked to a D1 database.

Some features of this comments system include:
- OAuth authorisation w/ GitHub

Future features include:
- Spam prevention through whitelisting
- Reactions
- Replies

## Requirements

- A `rust` installation, with the target `wasm32-unknown-unknown` installed, as CloudFlare
  Worker code is compiled into WebAssembly.
- Node.js, for the `npx` commands.

## Building

Before building, ensure that all Node modules are installed by running `npm install`.

Then, run the following commands:

```sh
# The `patches` folder includes a patch for `wrangler@4.36.0`. The Workers SDK is
# currently bugged with local redirects, the issue can be tracked here:
# https://github.com/cloudflare/workers-sdk/issues/5221
npx patch-package

# Set up the D1 database
npx wrangler d1 execute d1-comments --file schemas/schema.sql

# Run the CF Worker locally
npx wrangler dev --host=127.0.0.1 --port=8787 --env=dev
```

## Deploying

Simply run `npx wrangler deploy` to deploy the app to CloudFlare.
