# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

$ENV{'TEST_NGINX_BUILD_DIR'} = $ENV{'TRAVIS_BUILD_DIR'};

run_tests();

__DATA__
=== TEST 1: sqlite_database
sqlite_database
--- http_config
sqlite_database $TEST_NGINX_BUILD_DIR/build/test.db;
--- config
location = /sqlite_database {
    sqlite_query 'select * from test;';
}
--- request
GET /sqlite_database
--- error_code: 500
--- response_body
no such table: test



