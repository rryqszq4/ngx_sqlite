ngx_sqlite
==========
[ngx_sqlite](https://github.com/rryqszq4/ngx_sqlite) - Embedded sqlite for nginx-module.

Requirement
-----------
- sqlite 3
- nginx-1.6.3+

Installation
-------
```sh
$ git clone https://github.com/rryqszq4/ngx_sqlite.git

$ wget 'http://nginx.org/download/nginx-1.6.3.tar.gz'
$ tar -zxvf nginx-1.6.3.tar.gz
$ cd nginx-1.6.3

$ export SQLITE_INC=/path/to/sqlite
$ export SQLITE_LIB=/path/to/sqlite

$ ./configure --user=www --group=www \
              --prefix=/path/to/nginx \
              --add-module=/path/to/ngx_sqlite
$ make
$ make install
```

Synopsis
--------
nginx config:
```nginx
user www www;
worker_processes  4;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    keepalive_timeout  65;

    sqlite_database    test.db;
    sqlite_pragma "PRAGMA foreign_keys = ON;";
    server {
        listen       80;
        server_name  localhost;
    
        location /sqlite {
            sqlite_query "
                begin;
                    insert into test values (@test0, @test1);
                    select * from test where test0 == @test0 and test1 == @test1;
                end;
            ";
        }
        location /sqlite_json {
            sqlite_query_json "select * from test where test0== @test0 and test1 == @test1;";
        }
        location = /test {
            return 301 /sqlite?test0=test&test1=test;
        }
        location = /test_json {
            return 301 /sqlite_json?test0=test&test1=test;
        }
    }
}
````

TODO
---
* considering another interface for anonymous parameters.

Copyright and License
---------------------
BSD 2-Clause License

Copyright (c) 2017, rryqszq4  
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.