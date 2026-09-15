#!/usr/bin/env python3
"""Check a production Hugo build using only the Python standard library."""

import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit
from xml.etree import ElementTree


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.links, self.assets, self.images, self.schemas = [], [], [], []
        self.ids, self.meta, self.canonicals = set(), {}, []
        self.title, self.headings, self.redirect = "", 0, False
        self.in_title, self.in_schema, self.schema_text = False, False, ""
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("id"):
            self.ids.add(a["id"])
        if tag == "title":
            self.in_title = True
        if tag == "h1":
            self.headings += 1
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag == "meta":
            self.meta[a.get("name", a.get("property", ""))] = a.get("content", "")
            if a.get("http-equiv", "").lower() == "refresh":
                self.redirect = True
                self.links.append(a["content"].split("=", 1)[1].strip())
        if tag == "link" and "canonical" in a.get("rel", "").split():
            self.canonicals.append(a["href"])
        if tag == "link" and set(a.get("rel", "").split()) & {"stylesheet", "icon", "apple-touch-icon", "mask-icon"}:
            self.assets.append(a["href"])
        if tag in {"img", "script"} and a.get("src"):
            self.assets.append(a["src"])
        if tag == "img":
            self.images.append(a)
        if tag == "script" and a.get("type") == "application/ld+json":
            self.in_schema, self.schema_text = True, ""

    def handle_data(self, text):
        if self.in_title:
            self.title += text
        if self.in_schema:
            self.schema_text += text

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag == "script" and self.in_schema:
            self.schemas.append(json.loads(self.schema_text))
            self.in_schema = False


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "public").resolve()
    origin = "https://tavares.re/"
    pages, errors = {}, []
    for path in root.rglob("*.html"):
        text = path.read_text()
        if "<html" not in text.lower():
            continue  # Search-engine verification files are not web pages.
        rel = path.relative_to(root).as_posix()
        try:
            pages[rel] = Page(text)
        except (ValueError, KeyError) as exc:
            errors.append(f"{rel}: invalid metadata: {exc}")
            continue
        if re.search(r"XYZabc|UA-123-45|<AT>|%3cAT%3e|image path/url|link or path of image", text, re.I):
            errors.append(f"{rel}: template placeholder remains")

    for rel, page in pages.items():
        url = urljoin(origin, rel.removesuffix("index.html"))
        if not page.redirect:
            if not page.title or page.headings != 1:
                errors.append(f"{rel}: missing title or expected one H1, found {page.headings}")
            if not page.meta.get("description"):
                errors.append(f"{rel}: missing description")
            if page.canonicals != [url]:
                errors.append(f"{rel}: canonical does not match {url}")
            if page.meta.get("og:url") != url:
                errors.append(f"{rel}: social URL does not match canonical")
            for prop in ("og:image", "twitter:image"):
                if not page.meta.get(prop):
                    errors.append(f"{rel}: missing {prop}")
                else:
                    page.assets.append(page.meta[prop])
            if any(not img.get("alt") for img in page.images):
                errors.append(f"{rel}: image missing alternative text")
            for schema in page.schemas:
                if schema.get("url") != url:
                    errors.append(f"{rel}: schema URL does not match canonical")
                if schema.get("@type") == "BlogPosting" and schema.get("mainEntityOfPage") != url:
                    errors.append(f"{rel}: article schema points to another page")

        for href in page.links + page.assets:
            parsed = urlsplit(urljoin(url, href))
            if parsed.scheme == "mailto":
                if not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", unquote(parsed.path)):
                    errors.append(f"{rel}: invalid email link")
                continue
            if parsed.scheme not in {"http", "https"} or parsed.netloc != "tavares.re":
                continue
            target = root / unquote(parsed.path).lstrip("/")
            if target.is_dir():
                target /= "index.html"
            if not target.is_file():
                errors.append(f"{rel}: missing destination {href}")
            elif parsed.fragment and target.suffix == ".html":
                destination = pages.get(target.relative_to(root).as_posix())
                if destination and unquote(parsed.fragment) not in destination.ids:
                    errors.append(f"{rel}: missing fragment {href}")

    source = Path(__file__).resolve().parents[1]
    for post in (source / "content/posts").rglob("index.md"):
        if not (root / post.parent.name / "index.html").is_file():
            errors.append(f"Missing established article path: {post.parent.name}")
    for path in ("index.xml", "posts/index.xml", "sitemap.xml"):
        try:
            ElementTree.parse(root / path)
        except (OSError, ElementTree.ParseError) as exc:
            errors.append(f"{path}: invalid or missing XML: {exc}")
    if not (root / "404.html").is_file():
        errors.append("Missing 404 page")
    if (root / "CNAME").read_text().strip() != "tavares.re":
        errors.append("Unexpected custom domain")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Checked {len(pages)} HTML pages: titles, links, assets, canonicals, social metadata, schema, email, RSS, sitemap, and article paths passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
