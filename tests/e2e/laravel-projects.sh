#!/bin/sh
# Laravel projects on the SSH stand for laravel_server (docs/research/
# laravel_audit.md §5, contract L4). Files only - the check reads files and
# runs nothing in a project, so no PHP is needed here.
#   /var/www/shop        Laravel 10 (support ended): .env readable by all with
#                        APP_ENV=local and APP_DEBUG=true, storage 777, and an
#                        artisan inside vendor/ that the search must skip
#   /srv/blog            Laravel 12, .env 640 root:www-data with APP_DEBUG=true,
#                        but the config is cached with debug false - the cached
#                        value is the one in effect
#   /srv/api             a zero-downtime deploy: current -> releases/2; the old
#                        releases/1 has an open .env that must not be judged
#   /var/www/tool        artisan without laravel/framework: not a project
# The key and the password below are stand-only values the tests look for in
# the result, where they must never appear.
set -eu

project() {  # project <dir> <laravel version>
    mkdir -p "$1/vendor/composer" "$1/storage" "$1/bootstrap/cache"
    printf '#!/usr/bin/env php\n<?php\n' > "$1/artisan"
    printf '{"require": {"php": "^8.2", "laravel/framework": "^%s"}}\n' "${2%%.*}" > "$1/composer.json"
    printf '{"packages": [{"name": "laravel/framework", "version": "v%s"}], "dev": false}\n' "$2" \
        > "$1/vendor/composer/installed.json"
    chmod 775 "$1/storage" "$1/bootstrap/cache"
}

project /var/www/shop 10.0.0
printf 'APP_NAME=Shop\nAPP_ENV=local\nAPP_KEY=base64:ZTJlLXN0YW5kLWtleQ==\nAPP_DEBUG=true\nDB_PASSWORD=e2e-db-secret\n' \
    > /var/www/shop/.env
chmod 644 /var/www/shop/.env
chmod 777 /var/www/shop/storage
mkdir -p /var/www/shop/vendor/acme/tool
printf '#!/usr/bin/env php\n' > /var/www/shop/vendor/acme/tool/artisan

project /srv/blog 12.0.0
printf 'APP_ENV=local\nAPP_KEY=base64:ZTJlLXN0YW5kLWtleQ==\nAPP_DEBUG=true\n' > /srv/blog/.env
# what `php artisan config:cache` writes: a var_export of every setting
cat > /srv/blog/bootstrap/cache/config.php <<'PHP'
<?php return array (
  'app' =>
  array (
    'name' => 'Blog',
    'env' => 'production',
    'debug' => false,
    'key' => 'base64:ZTJlLXN0YW5kLWtleQ==',
  ),
  'database' =>
  array (
    'connections' =>
    array (
      'mysql' =>
      array (
        'password' => 'e2e-db-secret',
      ),
    ),
  ),
);
PHP
chown root:www-data /srv/blog/.env /srv/blog/bootstrap/cache/config.php
chmod 640 /srv/blog/.env /srv/blog/bootstrap/cache/config.php

project /srv/api/releases/1 12.0.0
printf 'APP_ENV=production\nAPP_DEBUG=true\n' > /srv/api/releases/1/.env
chmod 644 /srv/api/releases/1/.env
project /srv/api/releases/2 12.0.0
printf 'APP_ENV=production\nAPP_DEBUG=false\n' > /srv/api/releases/2/.env
chown root:www-data /srv/api/releases/2/.env
chmod 640 /srv/api/releases/2/.env
ln -s releases/2 /srv/api/current

mkdir -p /var/www/tool
printf '#!/usr/bin/env php\n' > /var/www/tool/artisan
printf '{"require": {"symfony/console": "^7.0"}}\n' > /var/www/tool/composer.json
