"""Fail-closed local asset validation, reusable as a Wrangler custom build hook."""
import argparse
import hashlib
import json
from pathlib import Path

from validate_production import audit

ROOT = Path(__file__).resolve().parents[1]


def validate(root, policy_path):
    root = Path(root).resolve()
    policy = json.loads((root / policy_path).read_text())
    wrangler = json.loads((root / 'wrangler.json').read_text())
    directory = policy['publicDirectory']
    if directory != 'public' or wrangler.get('assets', {}).get('directory') != './public':
        raise ValueError('Assets must use the isolated ./public directory')
    if wrangler.get('name') != policy['workerName']:
        raise ValueError('Worker identity differs from release policy')
    if wrangler.get('main') or wrangler.get('build', {}).get('command') != 'python3 scripts/validate_worker_release.py deployment/worker-release.json':
        raise ValueError('Unexpected Worker script or missing validation hook')
    if any((root / name).exists() for name in ['wrangler.toml', 'wrangler.jsonc', '.wrangler/deploy/config.json']):
        raise ValueError('Ambiguous Wrangler configuration')
    output = root / directory
    if output.is_symlink():
        raise ValueError('Public directory must not be a symlink')
    # Public validation facts only: no authoring configs or license manifests in release repos.
    config = policy["validation"]
    if config.get("images", {}).get("useImages"):
        raise ValueError("Release validation must not depend on authoring image manifests")
    result = audit(config, output)
    if not result['ready']:
        raise ValueError('Public security/SEO validation failed: ' + ', '.join(sorted({i['code'] for i in result['issues'] if i['severity'] == 'error'})))
    actual = {p.relative_to(output).as_posix(): {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size} for p in output.rglob('*') if p.is_file()}
    if actual != policy['files']:
        raise ValueError('Public files differ from the reviewed release manifest; regenerate and review before updating policy')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('policy', type=Path)
    args = parser.parse_args()
    try:
        result = validate(ROOT, args.policy)
    except (ValueError, KeyError, OSError, TypeError):
        parser.exit(1, 'FAIL: Worker public artifact/configuration validation failed; no upload authorized.\n')
    print(f"PASS: isolated Worker public artifact validated ({result['counts']['pages']} pages); source/config/docs/Git remain outside assets.")


if __name__ == '__main__':
    main()
