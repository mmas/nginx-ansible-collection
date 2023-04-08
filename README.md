# nginx-ansible-modules

Ansible module `nginx_site` to create NGINX `server` records.

## Installation

```bash
ansible-galaxy install git+https://github.com/mmas/nginx-ansible-modules.git
```

## Usage

Import the role `nginx-ansible-modules` to use `nginx_site` module.

Example:

```yaml
---
- hosts: nginx
  become: yes
  roles:
    - nginx-ansible-modules
  tasks:
    - name: Create and enable my site configuration with proxy server and letsencrypt certificates
      nginx_site:
        name: myawesomewebsite.com
        log_name: myawesomewebsite
        proxy_pass: http://192.168.1.25:8080
        sslcert: /etc/letsencrypt/live/myawesomewebsite.com/fullchain.pem
        sslkey: /etc/letsencrypt/live/myawesomewebsite.com/privkey.pem
      notify:
        - reload nginx
    - name: Create ans enable default server to redirect all sites to HTTPS
      nginx_site:
        name: default
        server_name: _
        listen:
          - 80 default_server
        redirect_to: https://$host$request_uri
      notify:
        - reload nginx
  handlers:
    - name: reload nginx
      service:
        name: nginx
        state: reloaded
```

## Parameters

```yaml
listen:
  description:
    - IPs or ports to listen.
    - They can include other directives like 'ssl' or 'default_server'.
    - https://nginx.org/en/docs/http/ngx_http_core_module.html#listen
  type: list
  elements: str
  default: [ 443 ssl ]
name:
  description:
    - Site name.
    - This will be the file name and server_name if not passed.
  type: str
  required: yes
server_name:
  description:
    - Server name directive.
    - If not passed, it will equal to name.
    - https://nginx.org/en/docs/http/ngx_http_core_module.html#server_name
  type: str
sslcert:
  description:
    - Path to the SSL certificate to use, if any.
    - https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate
  type: str
  aliases: [ ssl_certificate ]
sslkey:
  description:
    - Path to the SSL certificate secret key, if any
    - https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate_key
  type: str
  aliases: [ ssl_certificate_key ]
include_letsencrypt:
  description:
    - Whether to include or not Letsencrypt SSL options.
    - If the SSL certificate is passed and located in /etc/letsencrypt, this will be set as true
  type: bool
letsencrypt_options:
  description:
    - Path to the SSL options from Letsencrypt.
    - https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf
  type: str
  default: /etc/letsencrypt/options-ssl-nginx.conf
log_name:
  description:
    - Prefix of the log file names (access.log and error.log)
  type: str
log_dir:
  description:
    - Directory where the nginx logs are located
  type: str
  default: /var/log/nginx
access_log:
  description:
    - Path to the access log file.
    - It will be set automatically if log_name is passed to {log_dir}/{log_name}.access.log
    - https://nginx.org/en/docs/http/ngx_http_log_module.html#access_log
  type: str
error_log:
  description:
    - Path to the error log file.
    - It will be set automatically if log_name is passed to {log_dir}/{log_name}.error.log
    - https://nginx.org/en/docs/ngx_core_module.html#error_log
  type: str
proxy_pass:
  description:
    - Proxied server.
    - https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass
  type: str
  required: yes
proxy_http_version:
  description:
    - HTTP protocol version for proxying.
    - https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_http_version
  type: str
  default: 1.1
proxy_headers:
  description:
    - Request header passed to the proxied server.
    - https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header
  type: dict
  default:
    'Host': '$host',
    'X-Real-IP': '$remote_addr',
    'X-Forwarded-For': '$proxy_add_x_forwarded_for',
    'X-Forwarded-Proto': '$scheme',
    'Upgrade': '$http_upgrade',
    'Connection': '"upgrade"'
redirect_to:
  description:
    - URL to redirect if want to stop processing and return a redirect code
    - Not necessary to pass status code 301 along redirect_to
  type: str
status_code:
  description:
    - Text returned if wanted to stop processing and return a code
    - Either redirect_to or status_text required if wanted to redirect
    - https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return
  type: int
status_text:
  description:
    - HTTP code if wanted to stop processing and return a code
    - Either redirect_to or status_text required if wanted to redirect
    - https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return
  type: str
allowed_ips:
  description:
    - List of IPs allowed.
    - If any passed, any other IP will be denied
    - https://nginx.org/en/docs/http/ngx_http_access_module.html
  type: list
  elements: str
state:
  description:
    - When 'present', the site will be available.
    - When 'enabled', the site will be available and enabled.
    - When 'absent', the site will be disabled and unavailable.
  type: str
  choices: [ present, enabled, absent ]
  default: enabled
sites_available_dir:
  description:
    - Directory to save the available sites.
  type: str
  default: /etc/nginx/sites-available
sites_enabled_dir:
description:
    - Directory to save the enabled sites.
  type: str
  default: /etc/nginx/sites-enabled
```
