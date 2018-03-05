# OpenID Connect Reverse Proxy

A very basic HTTP reverse proxy that forwards HTTP requests to an upstream
server, adding the ID Token as an `Authorization: Bearer` style HTTP header.
It associates the ID Token to a Session Cookie. If the Session Cookie is
absent from incoming requests, an authentication redirect will be sent. This
is especially useful for the [Kubernetes Dashboard][kdb] when the Kubernetes
cluster is [secured via OpenID Connect][k8s-oidc].

[![Docker Repository on Quay](https://quay.io/repository/twz123/oidc-reverse-proxy/status "Docker Repository on Quay")](https://quay.io/repository/twz123/oidc-reverse-proxy)

[kdb]: https://github.com/kubernetes/dashboard
[k8s-oidc]: https://kubernetes.io/docs/admin/authentication/#openid-connect-tokens

## Alpha

This is a toy project! So: Use at your own risk!

## Usage

```
Usage of oidc-reverse-proxy:
  -alsologtostderr
    	log to standard error as well as files
  -bind-address string
    	 (default "127.0.0.1:8080")
  -client-id string
    	
  -client-secret string
    	
  -cookie-domain string
    	
  -cookie-http-only
    	 (default true)
  -cookie-name string
    	 (default "_oidc_authentication")
  -cookie-path string
    	
  -cookie-secure
    	 (default true)
  -extra-scopes string
    	
  -issuer-url string
    	 (default "https://accounts.google.com")
  -log_backtrace_at value
    	when logging hits line file:N, emit a stack trace
  -log_dir string
    	If non-empty, write log files in this directory
  -logtostderr
    	log to standard error instead of files
  -redirect-url string
    	
  -require-verified-email
    	 (default true)
  -session-inactivity-threshold string
    	 (default "5m")
  -stderrthreshold value
    	logs at or above this threshold go to stderr
  -tls-verify-issuer
    	 (default true)
  -tls-verify-upstream
    	 (default true)
  -upstream-url string
    	
  -v value
    	log level for V logs
  -vmodule value
    	comma-separated list of pattern=N settings for file-filtered logging
```

## Building

There's a `Makefile` that'll build a statically linked linux amd64 binary
using Docker. But I'm pretty sure that `go build` / `go install` will also
work.

## License

    MIT License

    Copyright (c) 2018 Tom Wieczorek

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
