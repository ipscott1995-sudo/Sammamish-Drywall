"""Offline production-output preflight; reports issues without publishing or changing data."""
import argparse
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse, unquote
import xml.etree.ElementTree as ET

from site_urls import SiteURLs
from deployment_security import inspect_output, safe_detail

ROOT = Path(__file__).resolve().parents[1]


class Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.items = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.items.append((tag, dict(attrs)))


def audit(config, output, live=False, images=None):
    output = Path(output)
    issues = inspect_output(config, output, ROOT, images)
    counts = {'pages': 0, 'images': 0, 'socialImages': 0}
    if issues:
        return {'ready': False, 'counts': counts, 'issues': issues, 'limits': 'Unsafe or incomplete public artifact; remaining checks skipped.'}
    routes = SiteURLs(config)
    domain = config['business']['domain']
    expected_tel = 'tel:' + config['business']['phoneTel']
    expected_form = config['business']['formUrl']
    expected_pages = ['index.html', 'about.html', 'contact.html', 'faq.html'] + [s['url'] for s in config['services']] + [p['url'] for p in config['locationPages']]
    sample_texts = [item['text'] for item in config.get('reviews', {}).get('items', [])] if config.get('reviews', {}).get('mode') == 'sample' else []

    def issue(code, page, detail, severity='error'):
        issues.append({'code': code, 'page': page, 'detail': safe_detail(detail), 'severity': severity})

    def asset(value, page):
        parsed = urlparse(value)
        hosting_asset = (parsed.scheme == 'https' and parsed.netloc == 'static.cloudflareinsights.com' and parsed.path.startswith('/beacon.min.js')) or (not parsed.netloc and re.fullmatch(r'/cdn-cgi/scripts/[a-z0-9]+/cloudflare-static/email-decode\.min\.js', parsed.path))
        if live and hosting_asset:
            issue('hosting-injected-asset', page, 'Known Cloudflare analytics/email script; excluded from artifact comparison', 'warning')
            return
        if parsed.scheme or parsed.netloc:
            if parsed.scheme != 'https' or parsed.netloc != domain:
                issue('asset-domain', page, value)
                return
        raw = Path(unquote(parsed.path).lstrip('/'))
        target = (output / raw).resolve()
        if '..' in raw.parts or not target.is_relative_to(output.resolve()) or not target.is_file():
            issue('missing-asset', page, value)

    for name in expected_pages:
        path = output / name
        if not path.is_file():
            issue('missing-page', name, 'Expected generated page is absent')
            continue
        html = path.read_text(encoding='utf-8')
        counts['pages'] += 1
        parsed = Elements(html)
        links = [a.get('href', '') for t, a in parsed.items if t == 'a']
        if expected_tel not in links or config['business']['phoneDisplay'] not in html:
            issue('missing-phone', name, 'Configured phone display/link is absent')
        if expected_form not in links:
            issue('missing-form', name, 'Configured form link is absent')
        if len([1 for t,a in parsed.items if t == 'link' and a.get('rel') == 'canonical']) != 1:
            issue('canonical-count', name, 'Expected exactly one canonical link')
        for marker in ['SAMPLE —', 'Example homeowner', 'fictional', 'layout preview', '{{', *sample_texts]:
            if marker in html:
                issue('preview-content', name, marker)
        for tag, a in parsed.items:
            if tag == 'meta':
                field = a.get('name', a.get('property', '')).lower()
                if field in ['robots', 'googlebot', 'googlebot-image'] and any(v in a.get('content', '').lower() for v in ['noindex', 'nofollow', 'noimageindex', 'none']):
                    issue('indexing-block', name, a.get('content'))
            if tag == 'link' and a.get('rel') == 'canonical':
                expected = routes.absolute(name)
                if a.get('href') != expected:
                    issue('canonical-mismatch', name, a.get('href'))
            if a.get('data-review-mode') == 'sample' or set(a.get('class', '').split()) & {'review-card', 'testimonial', 'testimonials-grid'}:
                issue('review-component', name, a.get('class', 'sample'))
            if tag == 'a':
                href = a.get('href', '')
                local = urlparse(href)
                if not local.netloc or local.netloc == domain:
                    filename = routes.physical(local.path)
                    normalized_path = '/' + local.path.lstrip('/')
                    legacy_home = filename == 'index.html' and normalized_path == '/index.html' and routes.style == 'html'
                    if filename in expected_pages and normalized_path != routes.path(filename) and not legacy_home:
                        issue('internal-url-style', name, href)
                if href.startswith('tel:') and href != expected_tel:
                    issue('phone-link-mismatch', name, href)
                if '/widget/form/' in href and href != expected_form:
                    issue('form-link-mismatch', name, href)
            if tag == 'img':
                counts['images'] += 1
                for field in ['src', 'srcset', 'sizes', 'alt', 'width', 'height', 'loading', 'decoding']:
                    if not a.get(field):
                        issue('image-attribute', name, field)
                asset(a.get('src', ''), name)
                for candidate in a.get('srcset', '').split(','):
                    parts = candidate.strip().split()
                    if len(parts) != 2 or not re.fullmatch(r'\d+w', parts[-1]):
                        issue('srcset-syntax', name, candidate)
                    elif parts:
                        asset(parts[0], name)
            if tag in ['script', 'link']:
                value = a.get('src') if tag == 'script' else a.get('href') if a.get('rel') == 'stylesheet' else None
                if value:
                    asset(value, name)
        for phone in sorted(set(re.findall(r'\(\d{3}\)\s*\d{3}-\d{4}', html))):
            if re.sub(r'\D', '', phone) != re.sub(r'\D', '', config['business']['phoneDisplay']):
                issue('conflicting-phone-copy', name, phone)
        for schema_text in re.findall(r'<script[^>]+type="application/ld\+json"[^>]*>(.*?)</script>', html, re.S):
            try:
                schema = json.loads(schema_text)
            except json.JSONDecodeError as e:
                issue('invalid-jsonld', name, str(e))
                continue
            def walk(value):
                if isinstance(value, dict):
                    types = value.get('@type', [])
                    if isinstance(types, str): types = [types]
                    if set(types) & {'Review', 'AggregateRating'}:
                        issue('review-schema', name, str(types))
                    for item in value.values(): walk(item)
                elif isinstance(value, list):
                    for item in value: walk(item)
            walk(schema)
        meta = {a.get('property', a.get('name')): a.get('content') for t, a in parsed.items if t == 'meta'}
        if not config.get('images', {}).get('useImages', False) and not meta.get('og:image') and not meta.get('twitter:image'):
            pass
        elif not meta.get('og:image') or meta.get('og:image') != meta.get('twitter:image'):
            issue('social-image-mismatch', name, str(meta.get('og:image')))
        else:
            asset(meta['og:image'], name)
            if not meta['og:image'].startswith('https://' + domain + '/'):
                issue('social-url-not-absolute', name, meta['og:image'])
            counts['socialImages'] += 1
        if len([1 for t, a in parsed.items if t == 'h1']) != 1:
            issue('h1-count', name, 'Expected one H1', 'warning')
    try:
        sitemap = ET.parse(output / 'sitemap.xml').getroot()
        ns = '{http://www.sitemaps.org/schemas/sitemap/0.9}'
        if sitemap.tag != ns + 'urlset':
            issue('sitemap-namespace', 'sitemap.xml', sitemap.tag)
        urls = [e.text for e in sitemap.iter() if e.tag.endswith('}loc') or e.tag == 'loc']
        expected_urls = {routes.absolute(p) for p in expected_pages}
        if set(urls) != expected_urls or len(urls) != len(expected_urls):
            issue('sitemap-coverage', 'sitemap.xml', str(urls))
    except (OSError, ET.ParseError) as e:
        issue('sitemap-read', 'sitemap.xml', str(e))
    robots = (output / 'robots.txt').read_text()
    if 'Sitemap: https://' + domain + '/sitemap.xml' not in robots or re.search(r'Disallow:\s*/\s*$', robots, re.M):
        issue('robots', 'robots.txt', 'Unexpected sitemap or blocking rule')
    return {'ready': not any(i['severity'] == 'error' for i in issues), 'counts': counts, 'issues': issues,
            'limits': 'Offline checks do not establish GHL call routing, live redirect/canonical parity, Cloudflare project settings, or authenticity of all business claims.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Production preflight; optional read-only live verification. Never publishes or deploys.')
    parser.add_argument('site_slug')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'output')
    parser.add_argument('--json', type=Path, help='Optional sanitized report path outside public output')
    parser.add_argument('--live', action='store_true', help='Also GET configured live hosts: private probes and public/SEO/contact checks')
    parser.add_argument('--include-www', action='store_true', help='Include apex and www in live checks without editing site data')
    args = parser.parse_args(argv)
    if args.json and args.json.resolve().is_relative_to(args.output_dir.resolve()):
        parser.error('Reports must remain outside the public output directory')
    from deployment_security import private_paths
    try:
        private_paths(args.site_slug)
        config = json.loads((ROOT / 'config' / f'config-{args.site_slug}.json').read_text())
        result = audit(config, args.output_dir)
        result['result'] = 'PASS' if result['ready'] else 'FAIL'
        if args.live and result['ready']:
            from live_validation import verify_live
            result['live'] = verify_live(config, args.site_slug, ROOT, args.output_dir, audit, args.include_www)
            result['ready'] = result['live']['ready']
            result['result'] = 'PASS' if result['ready'] else 'FAIL'
        elif args.live:
            result['live'] = {'result': 'SKIPPED', 'reason': 'Local preflight failed; no network requests made'}
    except (ValueError, KeyError, OSError, TypeError):
        result = {'ready': False, 'result': 'FAIL', 'issues': [{'code': 'validation-input', 'severity': 'error', 'detail': 'Invalid/missing configuration or validation inputs; sensitive details omitted'}]}
    text = json.dumps(result, indent=2)
    if args.json:
        args.json.write_text(text + '\n')
    print(text)
    return 0 if result['ready'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
