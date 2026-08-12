# FUTURE

Everything that was on this list is now built, except one item that was
reshaped:

* ~~Support for third-party auth using a handoff to a separate binary~~ — built
  as `auth.<name>.forward`: goproxy issues a subrequest to a URL and treats 2xx
  as success. That is the mechanism nginx spells `auth_request` and Traefik
  spells ForwardAuth, and it costs one HTTP call rather than one process fork
  per request. A binary handoff can satisfy the same interface by running as a
  long-lived subprocess behind a unix socket.
* ~~Support for multiple targets for the same rule match: load balancing,
  failover~~ — built as named upstreams: weighted `round_robin`, `least_conn`,
  `ip_hash` and `first_healthy` policies, passive and active health checking,
  and budgeted retries. See `examples/08-load-balancing.yaml`.

## Still open

* **Basic form handling (like contact us forms).** As written this means
  goproxy parses `application/x-www-form-urlencoded` bodies, validates fields
  and does something with them — email, spam handling, templating. That is an
  application, not a routing concern, and it is the one item on the original
  list that does not fit a proxy.

  The routing-shaped version of it is a **`webhook` action**: accept a form
  POST on a rule, convert it to JSON, forward it to a configured URL with a
  shared secret and a timeout, and answer the browser with a redirect or a
  canned response. Roughly:

  ```yaml
  rules:
    - name: contact
      match: { path: "/contact", methods: [POST] }
      webhook:
        url: "https://hooks.example.com/contact"
        secret_env: CONTACT_WEBHOOK_SECRET   # sent as an HMAC signature
        fields: [name, email, message]        # anything else is dropped
        max_body: 64KiB
        on_success: { redirect: "/thanks" }
        on_error:   { respond: { status: 502, body: "Could not send" } }
  ```

  That is about a hundred lines on top of what exists, and it stays a routing
  concern: no SMTP, no templating, no storage. It is not implemented.
