#!/bin/bash
# Copyright (c) 2018, rryqszq4 <rryqszq@gmail.com>

mkdir build
cd build
mkdir nginx

echo "nginx download ..."
wget http://nginx.org/download/nginx-${NGINX_SRC_VERSION}.tar.gz
echo "nginx download ... done"
tar xf nginx-${NGINX_SRC_VERSION}.tar.gz

NGINX_SRC=`pwd`'/nginx-'${NGINX_SRC_VERSION}
NGINX_SRC_ROOT=`pwd`'/nginx'
cd ${NGINX_SRC}


echo "nginx install ..."
./configure --prefix=${NGINX_SRC_ROOT} \
              --add-module=../../../ngx_sqlite
make
make install

if [ $? -eq 0 ];then
	echo "nginx install ... done"
	echo "ngx_sqlite compile success."
else
	echo "ngx_sqlite compile failed."
	exit 1
fi
