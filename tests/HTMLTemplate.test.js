import { describe, expect, it } from 'vitest'
import {
  enrichDocumentV2_0,
  enrichDocumentV2_1,
} from '../lib/enrichDocument.js'
import HTMLTemplate2_0 from '../lib/HTMLTemplate2_0.js'
import HTMLTemplate2_1 from '../lib/HTMLTemplate2_1.js'
import { renderMarkdown } from '../lib/markdownParser.js'

/**
 * Minimal but structurally valid CSAF 2.0 document, covering just enough
 * fields to exercise the full enrich -> renderMarkdown -> HTMLTemplate
 * pipeline.
 */
const minimalV2_0Doc = {
  document: {
    title: 'Test Advisory',
    category: 'csaf_base',
    csaf_version: '2.0',
    distribution: { tlp: { label: 'WHITE' } },
    lang: 'en',
    publisher: {
      category: 'vendor',
      name: 'Acme Inc',
      namespace: 'https://example.com',
    },
    tracking: {
      id: 'ACME-2024-001',
      status: 'final',
      version: '1',
      initial_release_date: '2024-01-01T00:00:00Z',
      current_release_date: '2024-01-01T00:00:00Z',
      revision_history: [
        { date: '2024-01-01T00:00:00Z', number: '1', summary: 'Initial' },
      ],
    },
    notes: [{ category: 'summary', text: '**Important** summary' }],
  },
  vulnerabilities: [
    {
      title: 'Example vuln',
      notes: [{ category: 'description', text: 'desc' }],
    },
  ],
}

/**
 * Minimal but structurally valid CSAF 2.1 document.
 */
const minimalV2_1Doc = {
  document: {
    title: 'Test Advisory 2.1',
    category: 'csaf_base',
    csaf_version: '2.1',
    distribution: { tlp: { label: 'WHITE' } },
    lang: 'en',
    publisher: {
      category: 'vendor',
      name: 'Acme Inc',
      namespace: 'https://example.com',
    },
    tracking: {
      id: 'ACME-2024-002',
      status: 'final',
      version: '1',
      initial_release_date: '2024-01-01T00:00:00Z',
      current_release_date: '2024-01-01T00:00:00Z',
      revision_history: [
        { date: '2024-01-01T00:00:00Z', number: '1', summary: 'Initial' },
      ],
    },
  },
  vulnerabilities: [],
}

describe('HTMLTemplate2_0 (end-to-end with enrichDocumentV2_0 + renderMarkdown)', () => {
  it('renders a full HTML document containing the advisory content', () => {
    const { document: enriched } = enrichDocumentV2_0(minimalV2_0Doc)
    const parsed = renderMarkdown(enriched)
    const html = HTMLTemplate2_0({ document: parsed })

    expect(html).toContain('<!DOCTYPE html>')
    expect(html).toContain('Test Advisory')
    expect(html).toContain('ACME-2024-001')
  })

  it('inlines the bundled CSS into <style> tags rather than <link>ing to external files', () => {
    const { document: enriched } = enrichDocumentV2_0(minimalV2_0Doc)
    const parsed = renderMarkdown(enriched)
    const html = HTMLTemplate2_0({ document: parsed })

    // The output must be a self-contained HTML document that doesn't depend
    // on any file path (relative or absolute) or network request resolving
    // correctly - it's opened directly from disk (CLI output) and/or
    // written into a blank iframe with no base URL (Secvisogram's preview),
    // neither of which can reliably resolve <link href="..."> references.
    expect(html).not.toContain('<link')
    expect(html).toContain('<style>')
    // Spot-check actual CSS content made it into the output, not just the tag.
    expect(html).toContain('Gutenberg')
  })

  it('renders markdown fields (processed by renderMarkdown) as real HTML, not escaped text', () => {
    const { document: enriched } = enrichDocumentV2_0(minimalV2_0Doc)
    const parsed = renderMarkdown(enriched)
    const html = HTMLTemplate2_0({ document: parsed })

    expect(html).toContain('<strong>Important</strong>')
  })

  it('HTML-escapes the document title (not a markdown field, double-brace interpolated)', () => {
    const doc = structuredClone(minimalV2_0Doc)
    doc.document.title = '<script>alert(1)</script>'
    const { document: enriched } = enrichDocumentV2_0(doc)
    const parsed = renderMarkdown(enriched)
    const html = HTMLTemplate2_0({ document: parsed })

    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).toContain('&lt;script&gt;')
  })
})

describe('HTMLTemplate2_1 (end-to-end with enrichDocumentV2_1)', () => {
  it('renders a full HTML document containing the advisory content', () => {
    const enriched = enrichDocumentV2_1(minimalV2_1Doc)
    const html = HTMLTemplate2_1(enriched)

    expect(html).toContain('<!DOCTYPE html>')
    expect(html).toContain('Test Advisory 2.1')
    expect(html).toContain('ACME-2024-002')
  })

  it('shows the CVSS version alongside the vector string/base score in the product status table', () => {
    const doc = /** @type {any} */ (structuredClone(minimalV2_1Doc))
    doc.product_tree = {
      full_product_names: [{ product_id: 'P1', name: 'Affected Product' }],
    }
    doc.vulnerabilities = [
      {
        metrics: [
          {
            products: ['P1'],
            content: {
              cvss_v4: {
                version: '4.0',
                baseScore: 9.8,
                vectorString: 'CVSS:4.0/TEST-VECTOR',
              },
            },
          },
        ],
        product_status: { known_affected: ['P1'] },
      },
    ]
    const enriched = enrichDocumentV2_1(doc)
    const html = HTMLTemplate2_1(enriched)

    expect(html).toContain('CVSS Version')
    expect(html).toContain('4.0')
    // `/` is HTML-escaped by Mustache's double-brace interpolation.
    expect(html).toContain('CVSS:4.0&#x2F;TEST-VECTOR')
    expect(html).toContain('9.8')
    expect(html).toContain('Affected Product')
  })
})
