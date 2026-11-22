<?php
// E2E stand, site wp2 (tests/e2e_wordpress/setup.sh): the usual hardening
// snippets - no generator tag (pages and feeds) and no public users list in
// the REST API. Author archives and the users sitemap are left as they are.
remove_action('wp_head', 'wp_generator');
add_filter('the_generator', '__return_empty_string');
add_filter('rest_endpoints', function ($endpoints) {
    unset($endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)']);
    return $endpoints;
});
