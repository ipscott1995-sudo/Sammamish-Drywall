"""Shared public-artifact policy and body-based private-path detection (no network)."""
import json
import re
from html import unescape
from pathlib import PurePosixPath

from site_media import SiteImages
from site_urls import SiteURLs

PRIVATE_DIRS = {'scripts', 'config', 'templates', 'docs', 'tests', 'agent', 'prompts', 'assets', '.git', '.github', '.deployment', '.venv', '__pycache__'}
ASSET_SUFFIXES = {'.css', '.js', '.webp', '.jpg', '.jpeg', '.png', '.svg', '.avif', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.webmanifest'}
SECRET_PATTERNS = [
    r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    r'\bgh[pousr]_[A-Za-z0-9]{30,}\b',
    r'\bAKIA[A-Z0-9]{16}\b',
    r'(?i)[\"\']?(?:api[_-]?key|api[_-]?token|access[_-]?token|client[_-]?secret|password|private[_-]?key|aws_secret_access_key|cloudflare_api_token)[\"\']?\s*[:=]\s*[\"\'][^\"\'\r\n]{4,}[\"\']',
]


def contains_credentials(text):
    return any(re.search(pattern, text) for pattern in SECRET_PATTERNS)


def safe_detail(value):
    text = str(value)
    if contains_credentials(text) or re.search(r'(?i)(?:token|secret|password|api[_-]?key|authorization|auth)=|https?://[^/\s@]+@', text):
        return '[sensitive value omitted]'
    return text


def public_path(value, page=False):
    """Do not let configuration turn authoring paths or symlinks into public assets."""
    if not isinstance(value, str) or not value or '\\' in value or any(c in value for c in ('?', '#', '%', ':')) or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid public output path')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or str(path) != value:
        raise ValueError('Public output path must be normalized and relative')
    if any(p.startswith('.') or p.lower() in PRIVATE_DIRS for p in path.parts):
        raise ValueError('Private/internal path cannot be a public asset')
    if page:
        if len(path.parts) != 1 or path.suffix != '.html':
            raise ValueError('Generated pages must be root-level HTML filenames')
    elif path.suffix.lower() not in ASSET_SUFFIXES:
        raise ValueError('Unsupported public asset type')
    return value


def expected_public_files(config, root, images=None):
    pages = {public_path(p, page=True) for p in SiteURLs(config).pages}
    images = images if images is not None else SiteImages(root, config)
    assets = {'css/styles.css', 'js/main.js'}
    assets.update(public_path(v['path']) for v in images.asset_variants())
    extra = config.get('deployment', {}).get('publicAssets', [])
    if not isinstance(extra, list):
        raise ValueError('deployment.publicAssets must be a list')
    assets.update(public_path(p) for p in extra)
    return pages | assets | {'robots.txt', 'sitemap.xml'}


def inspect_output(config, output, root, images=None):
    issues = []
    try:
        expected = expected_public_files(config, root, images)
    except (ValueError, KeyError, OSError, TypeError):
        return [{'code': 'public-policy', 'page': 'output', 'detail': 'Invalid public-file configuration or missing manifest assets', 'severity': 'error'}]
    if not output.is_dir() or output.is_symlink():
        return [{'code': 'output-directory', 'page': 'output', 'detail': 'Expected a real output directory', 'severity': 'error'}]
    expected_dirs = {parent.as_posix() for name in expected for parent in PurePosixPath(name).parents if parent.as_posix() != '.'}
    actual = set()
    for item in sorted(output.rglob('*')):
        name = item.relative_to(output).as_posix()
        code = None
        if item.is_symlink():
            code = 'output-symlink'
        elif any(p.startswith('.') or p.lower() in PRIVATE_DIRS for p in item.relative_to(output).parts):
            code = 'private-output-path'
        elif item.is_file():
            actual.add(name)
            if name not in expected:
                code = 'unexpected-public-file'
            elif item.suffix.lower() in {'.html', '.css', '.js', '.svg', '.txt', '.xml', '.webmanifest'}:
                if contains_credentials(item.read_text(encoding='utf-8', errors='replace')):
                    code = 'credential-in-output'
        elif item.is_dir():
            if name not in expected_dirs:
                code = 'unexpected-public-directory'
        else:
            code = 'unsupported-output-entry'
        if code:
            issues.append({'code': code, 'page': safe_detail(name), 'detail': 'Artifact rejected by public-file policy; contents omitted', 'severity': 'error'})
    for name in sorted(expected - actual):
        issues.append({'code': 'missing-public-file', 'page': name, 'detail': 'Expected public file is absent', 'severity': 'error'})
    return issues


def private_paths(slug):
    if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', slug):
        raise ValueError('Invalid site slug')
    return ['/scripts/generate_site.py', '/scripts/publish_site.py', '/scripts/site_media.py',
            f'/config/config-{slug}.json', f'/config/content-{slug}.json', f'/config/images-{slug}.json',
            '/config/config.json', '/templates/home.html', '/AGENTS.md', '/docs/architecture.md',
            '/variables.md', '/.git/HEAD', '/.env', '/requirements-images.txt']


def source_evidence(path, body, content_type):
    """Return a category only; never return source excerpts or credential values."""
    text = unescape(body.decode('utf-8', errors='replace'))
    if contains_credentials(text):
        return 'credential-signature'
    if re.search(r'(?m)^\s*(?:def\s+\w+\s*\(|from\s+[\w.]+\s+import\s|import\s+\w+|class\s+\w+[(:])', text):
        return 'python-source'
    if re.search(r'\{\{\s*[A-Z][A-Z_0-9]*\s*\}\}', text):
        return 'unrendered-template'
    if path.endswith('.md') and re.search(r'(?m)^#{1,6}\s+\S', text):
        return 'internal-document'
    if path == '/.git/HEAD' and re.match(r'(?:ref: refs/|[0-9a-f]{40}\s*$)', text):
        return 'git-metadata'
    if path == '/.env' and re.search(r'(?m)^[A-Z][A-Z0-9_]+\s*=', text):
        return 'environment-file'
    if path.startswith('/requirements') and re.search(r'(?m)^[\w.-]+(?:==|>=|~=)[\w.]+', text):
        return 'dependency-source'
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        value = None
    if isinstance(value, (dict, list)):
        # Small, explicit error envelopes are not configuration data.
        error_keys = {'error', 'message', 'status', 'code', 'detail', 'success'}
        if not isinstance(value, dict) or not value or not set(value) <= error_keys or any(isinstance(v, (dict, list)) for v in value.values()):
            return 'private-json'
    return None
