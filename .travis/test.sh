#!/bin/bash
# Copyright (c) 2018, rryqszq4 <rryqszq@gmail.com>
echo "ngx_sqlite test ..."
NGX_PATH=`pwd`'/build/nginx/sbin'
${NGX_PATH}/nginx -V
export PATH=${NGX_PATH}:$PATH
prove -r t
