# tavares.re

Personal research portfolio and CV, built with Hugo and the pinned PaperMod submodule.

## Preview and build

Use Hugo **0.134.2 extended**, matching `.hugo-version` and CI.

```sh
git submodule update --init
hugo server --bind 127.0.0.1
```

Production checks:

```sh
hugo --minify --panicOnWarning
python3 scripts/check_site.py public
```

The checker uses the Python standard library. Pull requests build and check the site. A push to `main` also publishes the generated files to the existing GitHub Pages branch.

## Content

- `content/_index.md`: homepage introduction.
- `content/about/index.md`: the single maintained CV/resume.
- `content/posts/`: original walkthroughs, publication summaries, and talks.
- `layouts/` and `assets/css/extended/site.css`: site-owned PaperMod overrides. Keep the theme submodule unchanged when customizing the site.

Research entries use `summary`, `description`, and `format`. External publications also use `sourceURL`; selected homepage entries use `featured`, `featuredOrder`, and `focus`. Keep established paths and original entry dates; a publisher may display a different update or publication date.

Contribution and outcome claims must be supported by the linked public publications. Preserve author credits, collective attribution, observation windows, and the distinction between records, IPs, and devices.

Research thumbnails use `thumbnail.image` and `thumbnail.alt`. The generated WebP images in `static/images/research/` appear in homepage research cards, article listings, and below each post header with a central 5:1 crop. Post-header images load eagerly; homepage and listing images load lazily. They are separate from social sharing images. Use each publication's original imagery and public research context as generation references, keep text out of the artwork, and maintain descriptive alternative text. Sources and final prompts are recorded in [docs/research-thumbnails.md](docs/research-thumbnails.md).

## Save the CV as PDF

Open **About / CV** and select **Print / Save PDF**, or use the browser's Print command. Choose **Save as PDF**, A4 or Letter paper, and 100% scale. Disable browser headers and footers to omit the browser-generated date and page URL.

The print stylesheet hides site navigation and controls, uses a white background in both themes, and preserves contact details and links. Maintain the About page directly; no separate PDF needs to be kept in sync.

## Social preview

`assets/social-card.svg` is the editable source for `static/images/social-card.png` (1200 × 630). Regenerate the PNG with an SVG renderer when changing the card. The SVG is a source asset; the PNG is served to social platforms.
