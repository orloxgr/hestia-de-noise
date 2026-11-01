"""Operator-selected rule suggestions, independent of installed applications."""
from policy import FILTER_AGENTS


def filtered(ident, parameters):
    return {'id': ident, 'enabled': True, 'path': '/', 'targets': [],
            'parameters': parameters, 'agents': list(FILTER_AGENTS),
            'action': 'limit', 'rate': 30, 'burst': 5}


def static(ident, path, extensions):
    return {'id': ident, 'enabled': True, 'path': path, 'targets': [], 'extensions': extensions}


RULES = {
    'static': [
        {'key': 'wp_maps', 'title': 'WordPress source maps',
         'description': '/wp-content/ · map',
         'rules': [static('wp_source_maps', '/wp-content/', ['map'])]},
        {'key': 'wp_assets', 'title': 'WordPress JS / CSS',
         'description': '/wp-content/plugins/, /wp-content/themes/, /wp-includes/ · js css map',
         'rules': [static('wp_plugin_assets', '/wp-content/plugins/', ['js', 'css', 'map']),
                   static('wp_theme_assets', '/wp-content/themes/', ['js', 'css', 'map']),
                   static('wp_core_assets', '/wp-includes/', ['js', 'css', 'map'])]},
    ],
    'filters': [
        {'key': 'product_filters', 'title': 'Product listing filters',
         'description': 'All paths · min_price, max_price, orderby · 30/minute/crawler/domain',
         'rules': [filtered('product_listing_filters', ['min_price', 'max_price', 'orderby'])]},
        {'key': 'directory_filters', 'title': 'VLM directory filters',
         'description': 'All paths · vlm_listing_tag, vlm_listing_category, vlm_listing_distance · 30/minute/crawler/domain',
         'rules': [filtered('vlm_listing_filters', ['vlm_listing_tag', 'vlm_listing_category', 'vlm_listing_distance'])]},
    ],
}
