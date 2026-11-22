#!/usr/bin/env bash
# WordPress E2E stand (docs/research/wordpress_audit.md, contract C6): two
# sites from the official images, the ground truth for wordpress_external.
#   wp1 http://127.0.0.1:8081/ - WordPress 6.4.3 (insecure per wordpress.org),
#       plain permalinks, contact-form-7 5.9, a public debug.log and a
#       wp-config.php.bak next to wp-config.php
#   wp2 http://127.0.0.1:8082/ - the same core with pretty permalinks; an
#       mu-plugin removes the generator tag and the REST users list
# Passwords are made per run and masked in the GitHub Actions log.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WP_IMAGE=wordpress:6.4.3-php8.2-apache
CLI_IMAGE=wordpress:cli-2.10-php8.2
DB_IMAGE=mariadb:11.4
DB_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
ADMIN_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
echo "::add-mask::$DB_PASSWORD"
echo "::add-mask::$ADMIN_PASSWORD"

docker network create wpnet
docker run -d --name wpdb --network wpnet -e MARIADB_ROOT_PASSWORD="$DB_PASSWORD" \
  -e MARIADB_DATABASE=wp1 -e MARIADB_USER=wp -e MARIADB_PASSWORD="$DB_PASSWORD" "$DB_IMAGE"
for _ in $(seq 60); do
  docker exec wpdb healthcheck.sh --connect --innodb_initialized >/dev/null 2>&1 && break
  sleep 2
done
docker exec wpdb healthcheck.sh --connect --innodb_initialized
docker exec wpdb mariadb -uroot -p"$DB_PASSWORD" -e "CREATE DATABASE wp2; GRANT ALL ON wp2.* TO 'wp'@'%';"

# the site name is also its database name
for site in wp1 wp2; do
  port=$([ "$site" = wp1 ] && echo 8081 || echo 8082)
  docker run -d --name "$site" --network wpnet -p "127.0.0.1:$port:80" \
    -e WORDPRESS_DB_HOST=wpdb -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD="$DB_PASSWORD" \
    -e WORDPRESS_DB_NAME="$site" "$WP_IMAGE"
done
for site in wp1 wp2; do
  for _ in $(seq 60); do
    docker exec "$site" test -f /var/www/html/wp-config.php && break
    sleep 2
  done
  docker exec "$site" test -f /var/www/html/wp-config.php
done

wp() {  # wp <site> <wp-cli args...>; www-data is uid 33 in the apache image
  local site=$1
  shift
  docker run --rm --user 33:33 --volumes-from "$site" --network wpnet \
    -e WORDPRESS_DB_HOST=wpdb -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD="$DB_PASSWORD" \
    -e WORDPRESS_DB_NAME="$site" -e WP_CLI_CACHE_DIR=/tmp/wp-cli-cache "$CLI_IMAGE" wp "$@"
}

for site in wp1 wp2; do
  port=$([ "$site" = wp1 ] && echo 8081 || echo 8082)
  wp "$site" core install --url="http://127.0.0.1:$port" --title="E2E $site" --admin_user=e2e-admin \
    --admin_password="$ADMIN_PASSWORD" --admin_email=e2e@example.test --skip-email
  wp "$site" plugin install contact-form-7 --version=5.9 --activate
done

docker exec wp1 sh -c "printf '[22-Nov-2026 10:00:00 UTC] PHP Warning:  e2e stand\n' > /var/www/html/wp-content/debug.log"
docker exec wp1 cp /var/www/html/wp-config.php /var/www/html/wp-config.php.bak

wp wp2 rewrite structure '/%postname%/'
docker exec wp2 mkdir -p /var/www/html/wp-content/mu-plugins
docker cp "$HERE/hide-version.php" wp2:/var/www/html/wp-content/mu-plugins/hide-version.php

for port in 8081 8082; do
  for _ in $(seq 30); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/")" = 200 ] && break
    sleep 2
  done
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/")" = 200 ]
done
echo "WordPress stand is up"
