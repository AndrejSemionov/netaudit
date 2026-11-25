<?php
// The project folder served as the site root, as on a host where the root was
// not set to public/ (tests/e2e_laravel/setup.sh, site lv2): an existing file
// is sent as it is - .env, the log, composer.lock, .git - and every other
// request goes to public/index.php, as Laravel's own server.php does.
$root = $_SERVER['DOCUMENT_ROOT'];
$path = urldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '/');
if ($path !== '/' && is_file($root . $path)) {
    return false;
}
require $root . '/public/index.php';
