# GoProxy

A high-performance HTTP/HTTPS proxy server written in Go, designed for reverse proxy, load balancing, and request forwarding scenarios.

## Features

- **HTTP/HTTPS Proxy**: Full support for both HTTP and HTTPS protocols
- **Serving Static Files**: Serve static files from a local directory
- **Redirects**: Redirect certin endpoints to different targets
- **Serve a custom response**: Server a custom response code and message
- **Authentication**: Support for token and user basic auth
- **Header management**: Allow removal, override and forwarding of headers and user names
- **Reverse Proxy**: Route requests to backend services
- **Request Filtering**: Filter requests based on various criteria
- **SSL/TLS Termination**: Handle SSL certificates and termination
- **Logging**: Comprehensive request and error logging
- **Configuration**: YAML-based configuration for easy setup

## Quick Start

### Download Binaries

Download the latest release from the [releases page](https://github.com/yourusername/goproxy/releases) for your platform.

### Basic Usage

1. Create a `config.yaml` file with your configuration
2. Run the proxy server:
   ```bash
   ./goproxy -config config.yaml
   ```

### Full Example Configuration

```yaml
log_level: info
listen_addr: ":8080" # if using letsencrypt, this must be :80
#tls:
#  listen_addr: ":443"
#  lets_encrypt:
#    email: "glonek@gmail.com"
#    domains:
#      - "localhost"
#      - "home.glonek.io"
#    cache_dir: "/var/lib/goproxy/letsencrypt"
#  certs:
#    cert_file: "snakeoil.crt"
#    key_file: "snakeoil.key"
rules:
  # proxy rule
  - domain_match: 'localhost'
    path_match: "/proxy"
    token_auth:
      tokens:
        - "token1"
        - "token2"
      token_auth_header: "X-TOKEN"
      forward_header: true
    basic_auth:
      user: "admin"
      password: "password"
      set_user_header: "X-USER"
      set_user_get_var: "userget"
    proxy_rule:
      proxy_url: "http://127.0.0.1:8081/service"
      proxy_target_accept_self_signed: false
      # if true, request will be http://127.0.0.1:8081/service/proxy/{path}
      # if false, request will be http://127.0.0.1:8081/service/{path}
      proxy_append_path: true
      proxy_remove_headers:
        - "User-Agent"
        - '^Sec-.*'
      proxy_set_headers:
        "X-BOB": "testcustomheader"
      proxy_rewrite_host_header: "example.com"
  # redirect rule
  - domain_match: 'localhost'
    path_match: "/redirect"
    redirect_rule:
      redirect_url: "http://192.168.4.32/bob"
      redirect_status_code: 301
  # serve rule
  - domain_match: 'localhost'
    path_match: "/serve"
    serve_rule:
      serve_local_dir: "./"
  # catch all, use respond_rule
  - respond_rule:
      respond_status_code: 403
      respond_body: "Forbidden"
```

## Configuration Reference

The configuration file uses YAML format and supports the following options:

### Top Level Options

- `log_level`: (string) Logging level. Valid values: "detail", "debug", "info", "warn", "error", "fail", "none"
- `listen_addr`: (string) Address and port to listen on for HTTP (e.g. ":8080"); if using letsencrypt in the TLS section, this must be set to ":80"
- `tls`: (object) TLS configuration
  - `listen_addr`: (string) Address and port to listen on for HTTPS (e.g. ":443") 
  - `lets_encrypt`: (object) Let's Encrypt configuration
    - `email`: (string) Email address for Let's Encrypt registration
    - `domains`: (array) List of domains to obtain certificates for
    - `cache_dir`: (string) Directory to store Let's Encrypt cache/certificates
  - `certs`: (object) Manual TLS certificate configuration
    - `cert_file`: (string) Path to certificate file
    - `key_file`: (string) Path to private key file

### Rules

The `rules` section contains an array of rule objects that define how requests should be handled. Rules are evaluated in order and the first matching rule is used.

Each rule can have the following fields:

- `domain_match`: (string) Domain name to match against request Host header; begin with '^' to use regex
- `path_match`: (string) Path prefix or regex to match against request URL path; begin with '^' to use regex
- `token_auth`: (object) Token-based authentication
  - `tokens`: (array) List of valid tokens
  - `token_auth_header`: (string) Header name to check for token (default: "X-TOKEN")
  - `forward_header`: (bool) Whether to forward auth header to backend (proxy target only)
- `basic_auth`: (object) HTTP Basic authentication
  - `user`: (string) Username
  - `password`: (string) Password  
  - `set_user_header`: (string) Optional header to set with authenticated username (proxy target only)
  - `set_user_get_var`: (string) Optional GET parameter to set with authenticated username (proxy or static file hosting targets only)

Rules must specify exactly one of the following actions:

#### proxy_rule
Proxies requests to another server
- `proxy_url`: (string) Target URL to proxy requests to
- `proxy_target_accept_self_signed`: (bool) Whether to accept self-signed certificates
- `proxy_append_path`: (bool) Whether to append matched path to target URL
- `proxy_remove_headers`: (array) Headers to remove from request
- `proxy_set_headers`: (object) Headers to add/override in request
- `proxy_rewrite_host_header`: (string) Override Host header sent to target

#### redirect_rule  
Redirects requests to another URL
- `redirect_url`: (string) URL to redirect to
- `redirect_status_code`: (int) HTTP status code for redirect (e.g. 301, 302)

#### serve_rule
Serves files from local directory
- `serve_local_dir`: (string) Local directory path to serve files from

#### respond_rule
Returns a static response; specify either a body string or file:
- `respond_status_code`: (int) HTTP status code to return
- `respond_body`: (string) Response body content
- `respond_body_file`: (string) File to read response body from
