# @secvisogram/html-template

A JavaScript library for rendering [CSAF](https://oasis-open.github.io/csaf-documentation/)
(Common Security Advisory Framework) documents (versions 2.0 and 2.1) to HTML,
using the same Mustache templates as [Secvisogram](https://github.com/secvisogram/secvisogram).

It is used by [`@secvisogram/cli`](https://github.com/secvisogram/cli) to
render CSAF documents from the command line, and by the Secvisogram web app
itself for its preview/export features.

## Installation

```sh
npm install @secvisogram/html-template
```

## Usage

Rendering a document is a two- (2.0) or three-step (2.1, if you also want
markdown fields converted to HTML) pipeline: enrich the raw CSAF document
with the data the template needs, optionally render markdown fields, then
render the HTML template.

### CSAF 2.0

```js
import {
  enrichDocumentV2_0,
  HTMLTemplate2_0,
  renderMarkdown,
} from '@secvisogram/html-template'

const csafDocument = JSON.parse(await readFile('advisory.json', 'utf8'))

const { document: enriched } = enrichDocumentV2_0(csafDocument)
const parsed = renderMarkdown(enriched)
const html = HTMLTemplate2_0({ document: parsed })
```

### CSAF 2.1

```js
import {
  enrichDocumentV2_1,
  HTMLTemplate2_1,
  renderMarkdown,
} from '@secvisogram/html-template'

const csafDocument = JSON.parse(await readFile('advisory.json', 'utf8'))

const { document: enriched } = enrichDocumentV2_1(csafDocument)
const parsed = renderMarkdown(enriched)
const html = HTMLTemplate2_1({ document: parsed })
```

> [!IMPORTANT]
> Always call `renderMarkdown` on the _enriched_ document (the return value
> of `enrichDocumentV2_0`/`enrichDocumentV2_1`), not the original raw
> document, and always pass its result into `HTMLTemplate2_0`/
> `HTMLTemplate2_1`. Skipping this step - or passing the wrong document -
> means markdown syntax (e.g. `**bold**`) in text fields such as notes,
> references, and remediation details will appear as raw, unrendered
> markdown in the output HTML.

## API

### `enrichDocumentV2_0(document)` / `enrichDocumentV2_1(document)`

Takes a raw, parsed CSAF 2.0 or 2.1 document (a plain object, as produced by
`JSON.parse`) and returns `{ document }`, a deep-cloned copy enriched with
the extra, denormalised data the Mustache templates rely on - for example:

- resolving `product_id`/`group_id` references (in `product_status`,
  `remediations`, `threats`, `product_groups`, ...) to include the
  product/group's display name
- attaching the matching CVSS vector string/base score (and, for CSAF 2.1,
  which CVSS version it came from) to each affected product
- computing `document.max_base_score`, the highest CVSS base score across
  all vulnerabilities
- splitting `notes` (both document-level and per-vulnerability) and
  `remediations`/`threats` into per-category buckets (e.g.
  `notes_summary`, `remediations_vendor_fix`, `threats_impact`, ...), sorted
  by date where applicable
- attaching the [Mustache lambda helpers](#mustache-lambda-helpers) the
  templates use, as properties on the returned document

The original input document is not mutated.

`enrichDocumentV2_0` reads CVSS data from `vulnerability.scores[].cvss_v3`
(the CSAF 2.0 shape, which only ever carries CVSS v3). `enrichDocumentV2_1`
reads it from `vulnerability.metrics[].content` (the CSAF 2.1 shape), where
`cvss_v2`, `cvss_v3`, and `cvss_v4` are all optional, independent siblings -
a single metric may carry more than one CVSS version at once. When more than
one is present, `enrichDocumentV2_1` prefers the highest version (v4, then
v3, then v2) as the "primary" score/vector shown for that product, and also
exposes which version was picked via `cvssVersion` on each resolved product
entry.

### `renderMarkdown(document)`

Renders [GitHub Flavored Markdown](https://github.github.com/gfm/) syntax to
HTML in a fixed allow-list of text fields (e.g. `document.notes[].text`,
`vulnerabilities[].remediations[].details`, ...) throughout the document,
mutating it in place, and also returning it. Fields not on the allow-list are
left untouched, even if they happen to contain markdown-like syntax.

If a field's content doesn't actually use any markdown syntax, it's left as
plain text rather than being wrapped in a `<p>` tag.

### `HTMLTemplate2_0({ document })` / `HTMLTemplate2_1({ document })`

Renders the enriched (and markdown-processed) document into a complete HTML
document string, using the bundled Mustache template for that CSAF version.
There is currently no way to supply a custom template.

### Mustache lambda helpers

`enrichDocumentV2_0`/`enrichDocumentV2_1` attach four
[Mustache lambdas](https://github.com/janl/mustache.js#lambdas) onto the
returned document, which the bundled templates invoke as e.g.
`{{#secureHref}}{{someUrl}}{{/secureHref}}`:

- **`secureHref`** - only emits an `href="..."` attribute if the URL's
  scheme (or, for `data:` URLs, MIME type) is on an allow-list
  (`#`, `mailto:`, `tel:`, `http(s):`, `ftp:`, and base64-encoded
  `image/png`, `image/jpeg`, or `image/gif` data URIs); otherwise renders
  nothing. This is a deliberate defense against untrusted advisory content
  (e.g. `javascript:` URLs) ending up as clickable links.
- **`upperCase`** - capitalises the first character of the rendered text.
- **`replaceUnderscores`** - replaces all `_` with spaces (e.g. for
  CSAF's `snake_case` category enum values).
- **`removeTrailingComma`** - strips a trailing comma from the rendered
  text (for comma-joined lists built with a trailing separator).

## Known limitations

- Templates are not customisable - `HTMLTemplate2_0`/`HTMLTemplate2_1`
  always use the bundled template.

## Rendered HTML output

The bundled `lib/css` stylesheets (a vendored copy of
[gutenberg-css](https://github.com/BafS/Gutenberg), plus Secvisogram's own
`preview.css`) are inlined directly into `<style>` tags in the rendered
HTML, rather than linked via `<link href="...">`. This makes the output a
single, self-contained HTML string/file with no separate network request or
file path that needs to resolve correctly - which matters both for
[`@secvisogram/cli`](https://github.com/secvisogram/cli)'s output (a
standalone file, possibly opened directly from disk) and for the
Secvisogram web app's preview (rendered into a blank `<iframe>` with no
base URL of its own, where relative/absolute file paths can't reliably
resolve at all).

## Development

```sh
npm install
npm test            # type-check, prettier --check, and run the test suite
npm run test-coverage
```
