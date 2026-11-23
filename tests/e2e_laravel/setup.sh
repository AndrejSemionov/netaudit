#!/usr/bin/env bash
# Laravel E2E stand (docs/research/laravel_audit.md §7, contract L6): two
# sites from the official skeleton, the ground truth for laravel_external.
#   lv1 http://127.0.0.1:8091/ - laravel/laravel 12 served from public/
#       (php artisan serve), APP_ENV=production, APP_DEBUG=false
#   lv2 http://127.0.0.1:8092/ - the same project served from the project
#       folder (router.php), the skeleton's own .env (APP_ENV=local,
#       APP_DEBUG=true), Telescope, Debugbar and Ignition installed, a log
#       line written by Laravel, a .git folder
# The runner image's PHP and Composer are used; the skeleton makes its app
# key per run.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
STAND=${RUNNER_TEMP:-/tmp}/laravel-stand
export COMPOSER_NO_INTERACTION=1
php -v | head -1
composer -V
php -m | grep -qi '^pdo_sqlite$'   # the skeleton's database

mkdir -p "$STAND"
composer create-project --prefer-dist laravel/laravel:^12.0 "$STAND/lv1"
cp -a "$STAND/lv1" "$STAND/lv2"

# lv1: production settings, served from public/
cd "$STAND/lv1"
sed -i -e 's/^APP_ENV=.*/APP_ENV=production/' -e 's/^APP_DEBUG=.*/APP_DEBUG=false/' .env
php artisan migrate --force
nohup php artisan serve --host=127.0.0.1 --port=8091 > "$STAND/lv1.log" 2>&1 &

# lv2: the skeleton's .env as it comes, debug tools, the project folder as the site root
cd "$STAND/lv2"
grep -q '^APP_ENV=local' .env
grep -q '^APP_DEBUG=true' .env
composer require laravel/telescope
php artisan telescope:install
composer require --dev barryvdh/laravel-debugbar spatie/laravel-ignition
php artisan migrate --force
php artisan tinker --execute="logger()->error('e2e stand');"
grep -q 'local.ERROR: e2e stand' storage/logs/laravel.log
git init -q .
nohup php -S 127.0.0.1:8092 -t "$STAND/lv2" "$HERE/router.php" > "$STAND/lv2.log" 2>&1 &

for port in 8091 8092; do
  for _ in $(seq 30); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/")" = 200 ] && break
    sleep 1
  done
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/")" = 200 ]
done
echo "Laravel stand is up"
