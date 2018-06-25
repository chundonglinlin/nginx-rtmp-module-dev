# ngx\_rtmp\_auto\_pull\_module

## Introduction

When auto pull turns on, someone play a stream, this module will check whether the stream is in current process or sibling worker process, and pull the stream inter processes if exists.

## Dependence

ngx\_rtmp\_auto\_pull\_module is dependent on: 

- ngx\_event\_multiport\_module
- ngx\_stream\_zone\_module

these two module came from [https://github.com/AlexWoo/nginx-multiport-module](https://github.com/AlexWoo/nginx-multiport-module). You can find more details from this project

## Directives

#### rtmp\_auto\_pull

	syntax:  rtmp_auto_pull on|off
	context: rtmp, server, application
	default: off

Turn on of turn off rtmp auto pull function.

#### rtmp\_auto\_pull\_port

	syntax:  rtmp_auto_pull_port addr
	context: rtmp, server, application
	default: unix:/tmp/rtmp_auto_pull.sock

Socket for pull stream inter processes. Addr can be unix, IPv4 or IPv6 multiport, same as multi_port configure in [multi_listen](https://github.com/AlexWoo/nginx-multiport-module#multi_listen) in ngx\_event\_multiport\_module.

## Test

Use conf file below, push a stream to core, and pull the stream from pull.

- start core

		/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.core.conf

- start pull

		/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.pull.conf

#### core

	user  root;
	worker_processes  4;

	error_log  logs/error.core.log  info;
	
	pid        logs/nginx.core.pid;
	
	rtmp_stream_zone  buckets=10007 streams=10000;
	
	events {
	    worker_connections  1024;
	    multi_listen unix:/tmp/rtmp_auto_pull.core 1937;
	}
	
	rtmp {
	    rtmp_auto_pull on;
	    rtmp_auto_pull_port unix:/tmp/rtmp_auto_pull.core;
	
	    server {
	        listen 1937;
	        application live {
	            live on;
	        }
	    }
	}
	
	
	http {
	    include       mime.types;
	    default_type  application/octet-stream;
	
	    sendfile        on;
	    keepalive_timeout  65;
	
	    #gzip  on;
	
	    server {
	        listen       8080;
	        server_name  localhost;
	
	        location / {
	            root   html;
	        }
	
	        error_page   500 502 503 504  /50x.html;
	        location = /50x.html {
	            root   html;
	        }
	    }
	}

#### pull

	user  root;
	worker_processes  4;

	error_log  logs/error.pull.log  info;
	
	pid        logs/nginx.pull.pid;
	
	rtmp_stream_zone  buckets=10007 streams=10000;
	
	events {
	    worker_connections  1024;
	    multi_listen unix:/tmp/rtmp_auto_pull.pull 1935;
	    multi_listen 11935 1935;
	}
	
	rtmp {
	    rtmp_auto_pull on;
	    rtmp_auto_pull_port unix:/tmp/rtmp_auto_pull.pull;
	
	    server {
	        listen 1935;
	        application live {
	            live on;
	            pull rtmp://127.0.0.1:1937/live;
	        }
	    }
	}
	
	
	http {
	    include       mime.types;
	    default_type  application/octet-stream;
	
	    sendfile        on;
	    keepalive_timeout  65;
	
	    server {
	        listen       80;
	        server_name  localhost;

	        location / {
	            root   html;
	        }

	        error_page   500 502 503 504  /50x.html;
	        location = /50x.html {
	            root   html;
	        }
	    }
	}