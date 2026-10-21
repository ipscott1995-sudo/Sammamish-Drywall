"""Public routes are independent of physical HTML and manifest placement filenames."""
import re
from urllib.parse import urlsplit, urlunsplit


class SiteURLs:
    def __init__(self, config):
        self.style = config.get('publicUrlStyle', 'html')
        if self.style not in ('html', 'extensionless'):
            raise ValueError('publicUrlStyle must be html or extensionless')
        self.origin = 'https://' + config['business']['domain']
        self.pages = ['index.html', 'about.html', 'contact.html', 'faq.html'] + [s['url'] for s in config['services']] + [p['url'] for p in config['locationPages']]

    def path(self, filename):
        if filename == 'index.html':
            return '/'
        return '/' + (filename.removesuffix('.html') if self.style == 'extensionless' else filename)

    def absolute(self, filename):
        return self.origin + self.path(filename)

    def rewrite(self, html):
        """Normalize quoted local page URLs in attributes and JSON-LD.

        Only registered page filenames are eligible; assets, external links,
        phone/form links, text and query/fragment contents are preserved.
        Legacy html-mode output is unchanged.
        """
        if self.style == 'html':
            return html

        def replace(match):
            quote, value = match.group(1), match.group(2)
            parsed = urlsplit(value)
            if parsed.netloc and (parsed.scheme + '://' + parsed.netloc != self.origin):
                return match.group(0)
            if parsed.scheme and not parsed.netloc:
                return match.group(0)
            filename = parsed.path.lstrip('/')
            if filename not in self.pages:
                return match.group(0)
            path = self.path(filename)
            value = urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))
            return quote + value + quote

        return re.sub(r'([\"\'])([^\"\'<>\s]+)\1', replace, html)

    def physical(self, public_path):
        """Resolve a public route to its build filename (local preview/checks)."""
        for filename in self.pages:
            if public_path in (self.path(filename), '/' + filename):
                return filename
        return public_path.lstrip('/')
