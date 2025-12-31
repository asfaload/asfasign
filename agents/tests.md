# TESTS
- All functionality of the code should be covered by tests
- Most functions should be covered by tests, testing the happy path as well as the unhappy path, checking the expected error is raise if needed
- If possible, design tests so that new tests are defined by data. An example is `test_check_groups_from_json_minimal` in `core/aggregate_signature/src/lib.rs`. The same test code is used to cover multiple situations: tests are defined in the vector `test_groups`, and the test code loops over this vector. Taking this approach should not be done at the cost of unreadable code though. Readable and maintainable code still has the priority, even for test code.

Tests of the whole project can be run with the command `cargo test` issued in the root of the repository, this takes some time.
The tests of each crate can as well be run with the same command issued in the crate's directory. This is much faster as fewer tests are run.
There are also integration tests run with the same command `cargo test`. In the core crates, there is a crate `integration_tests` that contains integration tests for the functionalities provided by the core crates.
The rest-api and client-cli crates also have integration tests.
