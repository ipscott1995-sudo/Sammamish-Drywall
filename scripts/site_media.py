"""Optional, manifest-driven local images and homepage-only reviews (no schema)."""

import json
import shutil
from html import escape
from pathlib import Path
from urllib.parse import urlparse


def local_path(root: Path, value: str, prefix: str = "") -> Path:
    """Reject absolute paths, traversal and symlinks outside the expected directory."""
    path = Path(value)
    base = (root / prefix).resolve()
    resolved = (root / path).resolve()
    if path.is_absolute() or ".." in path.parts or not resolved.is_relative_to(base):
        raise ValueError(f"Unsafe local asset path: {value}")
    return resolved


def https_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError(f"Expected a public HTTPS source URL: {value}")
    return escape(value, quote=True)


class SiteImages:
    def __init__(self, root: Path, config: dict, asset_root: Path = None):
        self.root = root
        self.asset_root = asset_root if asset_root is not None else root
        self.images = {}
        self.placements = {}
        self.social = {}
        settings = config.get("images", {})
        if not settings.get("useImages", False):
            return
        if not settings.get("manifest"):
            raise ValueError("Enabled images require images.manifest")
        manifest = json.loads(local_path(root, settings["manifest"], "config").read_text())
        if manifest.get("version") != 1:
            raise ValueError("Unsupported image manifest version")
        self.images = manifest["images"]
        self.placements = manifest["placements"]
        self.social = manifest.get("social", {"default": self.placements.get("index.html", {}).get("hero")})
        services = {s["slug"] for s in config["services"]}
        pages = {"index.html"} | {s["url"] for s in config["services"]}
        for page, sections in self.placements.items():
            if page not in pages:
                raise ValueError(f"Unsupported image page: {page}")
            allowed = {"hero", "about"} | {f"service:{slug}" for slug in services} if page == "index.html" else {"main", "detail"}
            for section, image_id in sections.items():
                if section not in allowed or image_id not in self.images:
                    raise ValueError(f"Invalid image placement: {page}/{section}/{image_id}")
        for image_id in self.used_ids():
            if image_id not in self.images:
                raise ValueError(f"Unknown image: {image_id}")
            item = self.images[image_id]
            if not item.get("alt", "").strip():
                raise ValueError(f"Missing alt text: {image_id}")
            source = item["source"]
            for field in ("creator", "license", "licenseDetails", "verifiedOn"):
                if not source.get(field):
                    raise ValueError(f"Missing image source {field}: {image_id}")
            https_url(source["url"])
            https_url(source["licenseUrl"])
            groups = [item] + list(item.get("renditions", {}).values())
            for group in groups:
                widths = []
                for variant in group.get("variants", []):
                    path = local_path(self.asset_root, variant["path"], "images/optimized")
                    if path.suffix not in {".webp", ".jpg"} or not path.is_file():
                        raise ValueError(f"Missing optimized image: {path}")
                    if variant["width"] <= 0 or variant["height"] <= 0:
                        raise ValueError(f"Invalid image dimensions: {image_id}")
                    widths.append(variant["width"])
                if not widths or widths != sorted(set(widths)):
                    raise ValueError(f"Image variants must have unique ascending widths: {image_id}")
        if self.social:
            valid_pages = pages | {"about.html", "contact.html", "faq.html"} | {p["url"] for p in config["locationPages"]}
            if set(self.social.get("pages", {})) - valid_pages:
                raise ValueError("Unknown social image page")
            for image_id in {self.social.get("default")} | set(self.social.get("pages", {}).values()):
                if image_id is not None and image_id not in self.images:
                    raise ValueError(f"Unknown social image: {image_id}")

    def used_ids(self):
        return sorted({image_id for sections in self.placements.values() for image_id in sections.values()} |
                      {i for i in [self.social.get("default"), *self.social.get("pages", {}).values()] if i})

    def asset_variants(self):
        for image_id in self.used_ids():
            item = self.images[image_id]
            yield from item["variants"]
            for rendition in item.get("renditions", {}).values():
                yield from rendition["variants"]

    def copy_assets(self, output: Path):
        for variant in self.asset_variants():
            target = output / variant["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(local_path(self.asset_root, variant["path"], "images/optimized"), target)

    def social_meta(self, config: dict, page: str) -> str:
        image_id = self.social.get("pages", {}).get(page, self.social.get("default"))
        if not image_id:
            return ""
        item = self.images[image_id]
        variants = item.get("renditions", {}).get("social", item)["variants"]
        variant = next((v for v in variants if v["width"] >= 1200), variants[-1])
        domain = config["business"]["domain"]
        parsed = urlparse("https://" + domain)
        if parsed.netloc != domain or parsed.path or parsed.query or parsed.fragment:
            raise ValueError("Social image domain must be a bare hostname")
        url = https_url(f'https://{domain}/{variant["path"]}')
        alt = escape(item["alt"], quote=True)
        mime = "image/jpeg" if variant["path"].endswith(".jpg") else "image/webp"
        return (f'<meta property="og:image" content="{url}">\n'
                f'<meta property="og:image:alt" content="{alt}">\n'
                f'<meta property="og:image:width" content="{variant["width"]}">\n'
                f'<meta property="og:image:height" content="{variant["height"]}">\n'
                f'<meta property="og:image:type" content="{mime}">\n'
                '<meta name="twitter:card" content="summary_large_image">\n'
                f'<meta name="twitter:image" content="{url}">\n'
                f'<meta name="twitter:image:alt" content="{alt}">\n')

    def figure(self, page: str, section: str) -> str:
        image_id = self.placements.get(page, {}).get(section)
        if not image_id:
            return ""
        item = self.images[image_id]
        kind = "card" if section.startswith("service:") else section
        variants = item.get("renditions", {}).get("card", item)["variants"] if kind == "card" else item["variants"]
        # A moderate fallback; srcset lets the browser select the appropriate DPR/viewport.
        fallback = next((v for v in variants if v["width"] >= 800), variants[-1])
        srcset = ", ".join(f'{v["path"]} {v["width"]}w' for v in variants)
        # These slot widths mirror styles.css: 1200px container, 40px gutters,
        # 260px card minimum/24px gaps/58px card inset; 1280px service layout.
        # Browser tests check this contract across grid and sidebar breakpoints.
        sizes = {
            "hero": "(max-width: 940px) calc(100vw - 40px), 900px",
            "card": "(max-width: 583.98px) calc(100vw - 98px), (max-width: 867.98px) calc(50vw - 90px), (max-width: 1151.98px) calc(33.333333vw - 87.333333px), (max-width: 1200px) calc(25vw - 86px), 214px",
            "about": "(max-width: 900px) calc(100vw - 40px), (max-width: 1200px) calc(50vw - 48px), 552px",
            "main": "(max-width: 768px) calc(100vw - 40px), (max-width: 900px) calc(100vw - 64px), (max-width: 1280px) calc(66.666667vw - 74.666667px), 778.666667px",
            "detail": "(max-width: 540px) calc(100vw - 40px), 500px",
        }[kind]
        loading = 'loading="eager" fetchpriority="high"' if kind == "hero" else 'loading="lazy"'
        portrait = fallback["height"] > fallback["width"] and kind in {"main", "detail"}
        if portrait:
            sizes = "(max-width: 400px) calc(100vw - 40px), 360px"
        modifier = " site-image--portrait" if portrait else ""
        return (
            f'<figure class="site-image site-image--{kind}{modifier}">'
            f'<img src="{escape(fallback["path"], quote=True)}" srcset="{escape(srcset, quote=True)}" '
            f'sizes="{escape(sizes, quote=True)}" alt="{escape(item["alt"], quote=True)}" '
            f'width="{fallback["width"]}" height="{fallback["height"]}" {loading} decoding="async">'
            '</figure>'
        )


def homepage_reviews(config: dict, preview: bool = False) -> str:
    settings = config.get("reviews", {})
    mode = settings.get("mode", "disabled")
    if mode not in {"disabled", "sample", "google"}:
        raise ValueError("reviews.mode must be disabled, sample, or google")
    if mode == "disabled" or (mode == "sample" and not preview):
        return ""
    items = settings.get("items", [])
    if not items:
        raise ValueError("Enabled reviews require items")
    sample = mode == "sample"
    cards = []
    for index, item in enumerate(items, 1):
        if not item.get("text", "").strip():
            raise ValueError("Review text is required")
        if sample:
            label = '<span class="review-label">SAMPLE — demonstration only</span>'
            author = f"Example homeowner {index} (fictional)"
            attribution = ""
        else:
            author = item["author"]
            if not author.strip():
                raise ValueError("Google review author is required")
            url = item["sourceUrl"]
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if host not in {"google.com", "www.google.com", "maps.google.com", "maps.app.goo.gl", "g.co"}:
                raise ValueError("Google reviews require a Google source URL")
            attribution = f'<a class="review-source" href="{https_url(url)}" target="_blank" rel="noopener">Read on Google</a>'
            rating = item.get("rating")
            if rating is not None and (type(rating) is not int or not 1 <= rating <= 5):
                raise ValueError("Review rating must be an integer from 1 to 5")
            label = f'<span class="review-label">Google review{f" · {rating}/5" if rating else ""}</span>'
        cards.append(
            f'<article class="review-card">{label}<blockquote><p>{escape(item["text"])}</p></blockquote>'
            f'<p class="review-author">{escape(author)}</p>{attribution}</article>'
        )
    heading = "Sample reviews — layout preview" if sample else "Customer reviews from Google"
    intro = "These fictional examples demonstrate the layout. They are not customer testimonials or Google reviews." if sample else "Read customer feedback and view each original review on Google."
    return (
        '<section class="section homepage-reviews" aria-labelledby="reviews-heading" data-review-mode="'
        + mode + '"><div class="container"><div class="section-header">'
        + f'<h2 id="reviews-heading">{heading}</h2><p class="reviews-notice">{intro}</p></div>'
        + '<div class="reviews-grid">' + "".join(cards) + '</div></div></section>'
    )
