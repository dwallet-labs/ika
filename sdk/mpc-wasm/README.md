## Build locally

To build the binary, you need to have Rust installed and then the `wasm-pack`.
The installation script [can be found here](https://rustwasm.github.io/wasm-pack/).

### Building for test (Node.js) environment

> required for tests.

```shell
pnpm build:dev
```

### Building for a Web environment

```shell
pnpm build:release
```

## Running tests

Local tests can only be run on the `dev` build.
To run tests, follow these steps:

```shell
pnpm build:dev
pnpm test
```
