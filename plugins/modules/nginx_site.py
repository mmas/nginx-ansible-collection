#!/usr/bin/python

DOCUMENTATION :  r'''
---
module: nginx-site
short_description: Create Nginx sites
author:
  - Modesto Mas (@mmas)
options:
  listen:
    description:
      - IPs or ports to listen.
      - They can include other directives like 'ssl' or 'default_server'.
      - Nginx documentation: https://nginx.org/en/docs/http/ngx_http_core_module.html#listen
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
      - Nginx documentation: https://nginx.org/en/docs/http/ngx_http_core_module.html#server_name
    type: str
  sslcert:
    description:
      - Path to the SSL certificate to use, if any.
      - Nginx documentation: https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate
    type: str
    aliases: [ ssl_certificate ]
  sslkey:
    description:
      - Path to the SSL certificate secret key, if any
      - Nginx documentation: https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate_key
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
      - A version of then can be found here: https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf
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
      - Nginx documentation: https://nginx.org/en/docs/http/ngx_http_log_module.html#access_log
    type: str
  error_log:
    description:
      - Path to the error log file.
      - It will be set automatically if log_name is passed to {log_dir}/{log_name}.error.log
      - Nginx documentation: https://nginx.org/en/docs/ngx_core_module.html#error_log
    type: str
  proxy_pass:
    description:
      - Proxied server.
      - Nginx documentation: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass
    type: str
    required: yes
  proxy_http_version:
    description:
      - HTTP protocol version for proxying.
      - Nginx documentation: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_http_version
    type: str
    default: 1.1
  proxy_headers:
    description:
      - Request header passed to the proxied server.
      - Nginx documentation: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header
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
      - Nginx documentation: https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return
    type: int
  status_text:
    description:
      - HTTP code if wanted to stop processing and return a code
      - Either redirect_to or status_text required if wanted to redirect
      - Nginx documentation: https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return
    type: str
  allowed_ips:
    description:
      - List of IPs allowed.
      - If any passed, any other IP will be denied
      - Nginx documentation: https://nginx.org/en/docs/http/ngx_http_access_module.html
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
'''

EXAMPLES = r'''
- name: Create my site configuration with proxy server and custom certificates
  nginx_site:
    name: myawesomewebsite.com
    log_name: myawesomewebsite
    proxy_pass: http://192.168.1.25:8080
    sslcert: /etc/ssl/certs/myawesomewebsite.com.crt
    sslkey: /etc/ssl/private/myawesomewebsite.com.pem
    state: present
  notify:
    - reload nginx

- name: Create and enable my site configuration with proxy server and letsencrypt certificates
  nginx_site:
    name: myawesomewebsite.com
    log_name: myawesomewebsite
    proxy_pass: http://192.168.1.25:8080
    sslcert: /etc/letsencrypt/live/myawesomewebsite.com/fullchain.pem
    sslkey: /etc/letsencrypt/live/myawesomewebsite.com/privkey.pem
  notify:
    - reload nginx

- name: Redirect all sites to HTTPS
  nginx_site:
    name: default
    server_name: _
    listen:
      - 80 default_server
    redirect_to: https://$host$request_uri
  notify:
    - reload nginx

- name: Create and enable a local site
  nginx_site:
    name: mysite.local
    log_name: mysite
    proxy_pass: http://192.168.1.25:9000
    allowed_ips:
      - 192.168.1.1
  notify:
    - reload nginx

- name: Disable mysite.local
  nginx_site:
    name: mysite.local
    state: present
  notify:
    - reload nginx

- name: Enable mysite.local
  nginx_site:
    name: mysite.local
  notify:
    - reload nginx

- name: Remove mysite.local
  nginx_site:
    name: mysite.local
    state: absent
  notify:
    - reload nginx
'''

RETURN = r'''#'''


import os

from ansible.module_utils.basic import AnsibleModule


PROXY_HTTP_VERSION = '1.1'
PROXY_HEADERS = {'Host': '$host',
                 'X-Real-IP': '$remote_addr',
                 'X-Forwarded-For': '$proxy_add_x_forwarded_for',
                 'X-Forwarded-Proto': '$scheme',
                 'Upgrade': '$http_upgrade',
                 'Connection': '"upgrade"'}
LETSENCRYPT_OPTIONS = '/etc/letsencrypt/options-ssl-nginx.conf'
LOG_DIR = '/var/log/nginx'
SITES_AVAILABLE_DIR = '/etc/nginx/sites-available'
SITES_ENABLED_DIR = '/etc/nginx/sites-enabled'


def render_site(listen,
                server_name,
                return_value,
                proxy_pass,
                sslcert=None,
                sslkey=None,
                letsencrypt_options=None,
                access_log=None,
                error_log=None,
                allowed_ips=(),
                proxy_http_version=PROXY_HTTP_VERSION,
                proxy_headers=PROXY_HEADERS):
    assert listen and proxy_pass or return_value
    lines = ['server {']

    for addr in listen:
        lines.append(f'    listen {addr};')

    lines.extend([f'    server_name {server_name};', ''])

    if sslcert and sslkey:
        lines.extend([f'    ssl_certificate {sslcert};',
                      f'    ssl_certificate_key {sslkey};'])
        if letsencrypt_options:
            lines.append(f'    include {letsencrypt_options};')
        lines.append('')

    if access_log:
        lines.append(f'    access_log {access_log};')
    if error_log:
        lines.append(f'    error_log {error_log};')
    if access_log or error_log:
        lines.append('')

    if return_value:
        lines.append(f'    return {return_value};')
    else:
        lines.append('    location / {')
        if allowed_ips:
            for ip in allowed_ips:
                lines.append(f'        allow {ip};')
            lines.append('        deny all;')
        lines.append(f'        proxy_pass {proxy_pass};')
        for name, value in proxy_headers.items():
            lines.append(f'        proxy_set_header {name} {value};')
        lines.append(f'        proxy_http_version {proxy_http_version};')
        lines.append('    }')

    lines.extend(['}', ''])
    return '\n'.join(lines)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            listen=dict(type='list', elements='str', default=['443 ssl']),
            name=dict(type='str', required=True),
            server_name=dict(type='str'),
            sslcert=dict(type='str', aliases=['ssl_certificate']),
            sslkey=dict(type='str', aliases=['ssl_certificate_key']),
            include_letsencrypt=dict(type='bool'),
            letsencrypt_options=dict(type='str', default=LETSENCRYPT_OPTIONS),
            log_name=dict(type='str'),
            log_dir=dict(type='str', default=LOG_DIR),
            access_log=dict(type='str'),
            error_log=dict(type='str'),
            proxy_pass=dict(type='str', no_log=False),
            proxy_http_version=dict(type='str', default=PROXY_HTTP_VERSION),
            proxy_headers=dict(type='dict', default=PROXY_HEADERS),
            redirect_to=dict(type='str'),
            status_code=dict(type='int'),
            status_text=dict(type='str'),
            allowed_ips=dict(type='list', elements='str'),
            state=dict(type='str',
                       choices=['present', 'enabled', 'absent'],
                       default='enabled'),
            sites_available_dir=dict(type='str', default=SITES_AVAILABLE_DIR),
            sites_enabled_dir=dict(type='str', default=SITES_ENABLED_DIR),
        ),
        supports_check_mode=True,
        required_together=['sslcert', 'sslkey'],
        mutually_exclusive=[['proxy_pass', 'status_code'],
                            ['proxy_pass', 'redirect_to']],
    )

    changed = False

    listen = module.params['listen']
    name = module.params['name']
    server_name = module.params['server_name'] or name
    sslcert = module.params['sslcert']
    sslkey = module.params['sslkey']
    include_letsencrypt = module.params['include_letsencrypt']
    letsencrypt_options = module.params['letsencrypt_options']
    log_name = module.params['log_name']
    log_dir = module.params['log_dir']
    access_log = module.params['access_log']
    error_log = module.params['error_log']
    proxy_pass = module.params['proxy_pass']
    proxy_http_version = module.params['proxy_http_version']
    proxy_headers = module.params['proxy_headers']
    redirect_to = module.params['redirect_to']
    status_code = module.params['status_code']
    status_text = module.params['status_text']
    allowed_ips = module.params['allowed_ips']
    state = module.params['state']
    sites_available_dir = module.params['sites_available_dir']
    sites_enabled_dir = module.params['sites_enabled_dir']

    # Assert paths exist.
    paths = [sites_available_dir, sites_enabled_dir]
    if sslcert:
        paths.extend([sslcert, sslkey])
    for path in paths:
        if not os.path.exists(path):
            module.fail_json(
                msg=f'Path {path} does not exist or not accessible',
                changed=changed)

    # Set status_code=301 if redirect_to provided.
    if redirect_to:
        status_code = 301
        status_text = redirect_to
    # Assert redirect_to if status_code=301.
    if status_code and 301 <= status_code <= 308 and not status_text:
        module.fail_json(msg='Redirect requires a redirect_to or status_text')
    if status_code:
        return_value = ' '.join([str(status_code), status_text or '']).rstrip()
    else:
        return_value = None

    # If certificate is from letsencrypt, include letsencrypt options if
    # include_letsencrypt not specified.
    if sslcert \
            and sslcert.startswith('/etc/letsencrypt') \
            and include_letsencrypt is None:
        include_letsencrypt = True

    # Define log paths
    log_name = module.params['log_name']
    log_dir = module.params['log_dir']
    if not access_log and log_name and log_dir:
        access_log = os.path.join(log_dir, f'{log_name}.access.log')
    if not error_log and log_name and log_dir:
        error_log = os.path.join(log_dir, f'{log_name}.error.log')

    site_available_file = os.path.join(sites_available_dir, name)
    site_enabled_file = os.path.join(sites_enabled_dir, name)

    if state == 'absent':
        if module.check_mode:
            module.exit_json(changed=changed)
        if os.path.exists(site_enabled_file):
            os.remove(site_enabled_file)
            changed = True
        if os.path.exists(site_available_file):
            os.remove(site_available_file)
            changed = True
        module.exit_json(changed=changed)

    if proxy_pass or return_value:
        kwargs = {
            'listen': listen,
            'server_name': server_name,
            'sslcert': sslcert,
            'sslkey': sslkey,
            'access_log': access_log,
            'error_log': error_log,
            'proxy_pass': proxy_pass,
            'proxy_http_version': proxy_http_version,
            'proxy_headers': proxy_headers,
            'return_value': return_value,
            'allowed_ips': allowed_ips,
        }
        if include_letsencrypt:
            kwargs['letsencrypt_options'] = letsencrypt_options
        site = render_site(**kwargs)
    else:
        site = None

    if os.path.exists(site_available_file):
        with open(site_available_file) as infile:
            current_site = infile.read()
    else:
        current_site = None

    if not current_site and not site:
        module.fail_json(msg='Site not found, create it using proxy_pass, '
                             'status_code or redirect_to')

    if module.check_mode:
        module.exit_json(changed=changed)

    if site and current_site != site:
        with open(site_available_file, 'w') as infile:
            infile.write(site)
        changed = True

    if state == 'enabled':
        if not os.path.exists(site_enabled_file) \
                or os.path.islink(site_enabled_file) \
                and os.readlink(site_enabled_file) != site_available_file:
            os.symlink(site_available_file, site_enabled_file)
            changed = True
    elif os.path.exists(site_enabled_file):
        os.remove(site_enabled_file)
        changed = True

    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
