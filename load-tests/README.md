# MPC Recovery Load Tests
This directory contains load tests for the MPC Recovery service. It is build using [Goose](https://book.goose.rs/title-page.html), a load testing tool written in Rust.

## Running the tests
To run the tests, you need to have Rust installed. You can install Rust using [rustup](https://rustup.rs/).
To start the tests, run the following command:
```bash
cargo run --release -- --host <host> --report-file=load_test_results.html --test-plan "$(cat ./test_plans/short.txt)" --scenarios simplempcpublickey
```
You can run Load Tests against your local development environment (check `/integration-tests` for more info) or against the staging environment by setting the `--host` parameter.

The tests are written in Rust and can be found in the `/src` directory.
You can create your own test plan or execute one of the existing test plans from `/test_plans` directory. 
