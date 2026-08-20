# Runbook: Web Terminal "Stuck on Login Screen" (nginx regex-capture regression)

Applies when a web-terminal host suddenly refuses login: users enter correct
credentials, the page reloads, and it bounces right back to `/login` (or the
terminal panes show the login form). This is a **host-level nginx problem**, not
an auth.py problem — the fix below has already been applied to the repo, so this
runbook is mainly for **older hosts still running the broken nginx build** or for
when Ubuntu ships a similar regression again.

---

## 1. Symptom

- Login POST succeeds server-side (a new ttyd is spawned and listens).
- The SPA loads, but every terminal iframe (`/ut/<port>/...`) is redirected to
  `/login` (`302`).
- From the CLI:

```bash
# Craft a valid cookie for a live ttyd port (see "Gather facts" below), then:
curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}\n" \
  -H "Host: <hostname>" -H "Cookie: <session-cookie>" \
  http://127.0.0.1:7680/ut/<port>/
# Expect 200. Broken host returns: 302 -> /login
```

## 2. Root cause (one paragraph)

Ubuntu's `nginx` package upgraded to `1.24.0-2ubuntu7.16` (and newer) builds
nginx 1.24.0 against **PCRE2** (stock nginx 1.24.0 only supports PCRE1, Ubuntu
patches it). In that build, positional regex captures (`$1`, `$2`) inside
`location ~` blocks are not populated correctly. The web terminal's nginx config
relies on `$1` to extract the per-user ttyd port:

```nginx
location ~ ^/ut/(\d+)/(.*) {
    set $ttyd_port $1;        # broken: becomes "/ut/" instead of "7750"
    auth_request /api/auth;   # subrequest now sends "X-TTYD-Port: /ut/"
```

auth.py's `/api/auth` rejects any request whose `X-TTYD-Port` does not equal the
port bound in the session cookie, so the terminal iframes get `401` and nginx
redirects them to `/login` — hence the endless login loop. The `/vnc-ws/<port>/`
location (remote desktop) had the same `$1` bug and returned `500`.

---

## 3. Diagnosis (confirm before fixing)

### 3.1 Check the nginx build

```bash
nginx -V 2>&1 | head -1                          # version, e.g. 1.24.0-2ubuntu7.16
ldd /usr/sbin/nginx | grep -i pcre              # libpcre2-8 => PCRE2 build
```

A `1.24.0-2ubuntu7.16+` binary linked against `libpcre2` is the smoking gun.
Also check the upgrade history:

```bash
grep -E 'nginx' /var/log/dpkg.log | tail -5      # when was nginx upgraded?
```

### 3.2 Reproduce the broken capture in isolation

Write a throwaway config and run a second nginx on a scratch port. No need to
touch the production config.

```nginx
# /tmp/repro.conf
worker_processes 1;
pid /tmp/repro.pid;
events { worker_connections 64; }
http {
    server {
        listen 7799;
        location ~ ^/ut/(\d+)/(.*) {
            return 200 "one=[$1] two=[$2] uri=[$uri]";
        }
    }
}
```

```bash
sudo nginx -c /tmp/repro.conf -p /tmp
curl -s http://127.0.0.1:7799/ut/7750/
# Healthy nginx:  one=[7750] two=[] uri=[/ut/7750/]
# Broken nginx:   one=[/ut/] two=[] uri=[/ut/7750/]     <-- regression
sudo kill $(cat /tmp/repro.pid)
```

### 3.3 Confirm the port header reaching auth.py

Watch what the internal auth subrequest actually sends:

```bash
sudo tcpdump -i lo -A -s0 'tcp port 7682' &
curl -s -o /dev/null -H "Cookie: <session-cookie>" \
  -H "Host: <hostname>" http://127.0.0.1:7680/ut/<port>/
sudo kill %1
# Broken host shows:  X-TTYD-Port: /ut/
# Healthy host shows: X-TTYD-Port: <port>
```

---

## 4. Fix

### 4.1 Permanent fix (edit the repo, deploy everywhere)

Switch the two dynamic-port regex locations from positional captures to
**named captures** (`(?<name>...)`). Named captures bind to their own variables
and are never clobbered by the last-executed-regex behavior; they are supported
by both PCRE1 and PCRE2 nginx, so the change is safe on every host.

Edit **`nginx/ttyd.conf`**:

```diff
-    location ~ ^/ut/(\d+)/(.*) {
-        set $ttyd_port $1;
+    location ~ ^/ut/(?<ttyd_port>\d+)/(?<ttyd_path>.*) {
         auth_request /api/auth;
         error_page 401 = @login_redirect;
 
-        proxy_pass http://127.0.0.1:$1/$2$is_args$args;
+        proxy_pass http://127.0.0.1:$ttyd_port/$ttyd_path$is_args$args;
```

```diff
-    location ~ ^/vnc-ws/(\d+)/(.*) {
+    location ~ ^/vnc-ws/(?<vnc_port>\d+)/(?<vnc_path>.*) {
         auth_request /api/auth;
         error_page 401 = @login_redirect;
 
-        proxy_pass http://127.0.0.1:$1/$2$is_args$args;
+        proxy_pass http://127.0.0.1:$vnc_port/$vnc_path$is_args$args;
```

**Mirror the same edit in `cf_tunnel_install.sh`** — it embeds its own copy of
this nginx template (search for `location ~ ^/ut/(\d+)/(.*)`; remember its
heredoc escapes `$` as `\$`). Keep both files in sync.

Then deploy:

```bash
./deploy.sh        # regenerates /etc/nginx/sites-available/<hostname>.conf and reloads
```

### 4.2 Hot-fix one host without a full deploy

Regenerate the effective config exactly as deploy.sh does (substitute the
tunnel hostname for the template's `server_name`), back up, install, reload:

```bash
hostname="$(grep -E '^\s*-\s*hostname:' ~/.cloudflared/config.yml | head -1 | awk '{print $NF}' | tr -d '"')"
conf="/etc/nginx/sites-available/${hostname}.conf"
sed "s/server_name mics5070wsl.micstec.com;/server_name ${hostname};/" nginx/ttyd.conf > /tmp/effective.conf

sudo cp "$conf" "$conf.bak.$(date +%Y%m%d_%H%M%S)"
sudo cp /tmp/effective.conf "$conf"
sudo nginx -t && sudo nginx -s reload
```

---

## 5. Verify

```bash
# 1. Config still valid after reload
sudo nginx -t

# 2. The /ut/ route now passes the correct port to auth.py
curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}\n" \
  -H "Host: <hostname>" -H "Cookie: <valid session cookie>" \
  http://127.0.0.1:7680/ut/<live-ttyd-port>/
# Expect: 200 (broken host returned 302 -> /login)

# 3. Cross-port access is still denied (port bound in cookie must match URL port)
#    with a cookie bound to port A, requesting /ut/<portB>/ must still return 302 -> /login

# 4. Through the public tunnel (same checks over https://<hostname>/ut/<port>/)

# 5. If nginx -T/logs show the subrequest: X-TTYD-Port should be the numeric port.
```

No auth.py restart is needed. Users who were mid-login may need to log out/in
once so the browser drops a stale session cookie.

---

## 6. Reference commands / facts

| Item | Value |
|------|-------|
| Breaking nginx package | `1.24.0-2ubuntu7.16` (and later) on Ubuntu |
| Affected config | `nginx/ttyd.conf` + embedded template in `cf_tunnel_install.sh` |
| Affected routes | `location ~ ^/ut/(\d+)/(.*)`, `location ~ ^/vnc-ws/(\d+)/(.*)` |
| Symptom marker in tcpdump | `X-TTYD-Port: /ut/` instead of the port number |
| auth.py endpoint doing the rejection | `GET /api/auth` (path `/api/auth` in `do_GET`) |
| Root doc for the codebase | `CODEBASE.md`, `CLAUDE.md` |