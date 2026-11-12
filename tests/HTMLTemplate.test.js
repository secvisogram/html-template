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

  it('renders vulnerability-level legal_disclaimer notes', () => {
    // Regression test: the template computed notes_legal_disclaimer for
    // each vulnerability (via addVulnerabilityNotesPreviewAttributes) but
    // never actually rendered it anywhere, unlike every other note
    // category, which silently dropped these notes from the output.
    const doc = /** @type {any} */ (structuredClone(minimalV2_0Doc))
    doc.vulnerabilities = [
      {
        title: 'Example vuln',
        notes: [
          {
            category: 'legal_disclaimer',
            title: 'Disclaimer',
            text: 'Vulnerability-level legal disclaimer text',
          },
        ],
      },
    ]
    const { document: enriched } = enrichDocumentV2_0(doc)
    const parsed = renderMarkdown(enriched)
    const html = HTMLTemplate2_0({ document: parsed })

    expect(html).toContain('Vulnerability-level legal disclaimer text')
  })

  it("renders a product group's markdown summary consistently, whether shown directly or referenced via group_ids", () => {
    // Regression test: product_tree.product_groups[].summary is a markdown
    // field, and enrichDocument copies it into `group_ids[].name` on every
    // remediation/threat that references that group - but that's a plain
    // string copy, not a shared reference, so it used to need its own
    // markdown field entry (it didn't have one) and its own {{{triple-brace}}}
    // template interpolation (it was double-brace, which would otherwise
    // double-escape the now-rendered HTML into literal `&lt;p&gt;...` text).
    const doc = /** @type {any} */ (structuredClone(minimalV2_0Doc))
    doc.product_tree = {
      product_groups: [
        { group_id: 'G1', summary: '**Bold Group**', product_ids: [] },
      ],
    }
    doc.vulnerabilities = [
      {
        title: 'Example vuln',
        remediations: [{ category: 'vendor_fix', group_ids: ['G1'] }],
        threats: [{ category: 'impact', group_ids: ['G1'] }],
      },
    ]
    const { document: enriched } = enrichDocumentV2_0(doc)
    const parsed = renderMarkdown(enriched)
    const html = HTMLTemplate2_0({ document: parsed })

    // Rendered directly (product_tree.product_groups[].summary).
    expect(html).toContain('<b><p><strong>Bold Group</strong></p></b>')
    // Rendered via remediation.group_ids[].name.
    expect(html).toContain('<li><p><strong>Bold Group</strong></p></li>')
    // Never appears as raw, unrendered markdown or double-escaped HTML.
    expect(html).not.toContain('**Bold Group**')
    expect(html).not.toContain('&lt;strong&gt;')
  })
})

describe('HTMLTemplate2_0 (CSAF 2.0 specific content)', () => {
  it('renders the publisher contact_details string', () => {
    const doc = /** @type {any} */ (structuredClone(minimalV2_0Doc))
    doc.document.publisher.contact_details = 'Reach us at CONTACT_DETAILS_20'
    const html = HTMLTemplate2_0(enrichDocumentV2_0(doc))

    expect(html).toContain('Reach us at CONTACT_DETAILS_20')
  })

  it('renders vulnerability-level involvements', () => {
    const doc = /** @type {any} */ (structuredClone(minimalV2_0Doc))
    doc.vulnerabilities[0].involvements = [
      {
        party: 'vendor',
        status: 'in_progress',
        date: '2024-02-01T00:00:00Z',
        summary: 'INVOLVEMENT_SUMMARY_20',
      },
    ]
    const html = HTMLTemplate2_0(enrichDocumentV2_0(doc))

    expect(html).toContain('<h4>Involvement</h4>')
    expect(html).toContain('Vendor (in progress)')
    expect(html).toContain('INVOLVEMENT_SUMMARY_20')
  })

  it('does not render any CSAF 2.1-only section', () => {
    const html = HTMLTemplate2_0(enrichDocumentV2_0(minimalV2_0Doc))

    expect(html).not.toContain('License expression')
    expect(html).not.toContain('<h5>Unknown</h5>')
    expect(html).not.toContain('<h4>Metrics</h4>')
    expect(html).not.toContain('First known exploitation dates')
  })

  it('spells the "Under investigation" heading correctly', () => {
    const doc = /** @type {any} */ (structuredClone(minimalV2_0Doc))
    doc.product_tree = { full_product_names: [{ product_id: 'P1', name: 'N' }] }
    doc.vulnerabilities[0].product_status = { under_investigation: ['P1'] }
    const html = HTMLTemplate2_0(enrichDocumentV2_0(doc))

    expect(html).toContain('<h5>Under investigation</h5>')
    expect(html).not.toContain('investgation')
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

  it('does not render a stray, always-empty {{$schema}} placeholder', () => {
    // Regression test: an unlabelled <p>{{$schema}}</p> with no
    // corresponding field ever set anywhere in enrichDocument - and no
    // 2.0 equivalent - used to render an empty <p></p> in every document.
    const enriched = enrichDocumentV2_1(minimalV2_1Doc)
    const html = HTMLTemplate2_1(enriched)

    expect(html).not.toContain('$schema')
    expect(html).not.toContain('<p></p>\n  <h1>')
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

  it('shows the document-level max base score header labelled with the CVSS version that actually produced it', () => {
    // Regression test: the header used to always say "CVSSv3.1 Base Score"
    // regardless of which CVSS version the score actually came from. Using
    // cvss_v2 here (neither v3 nor v4) proves the label is genuinely
    // computed from the winning score, not just switched between two
    // hardcoded options.
    const doc = /** @type {any} */ (structuredClone(minimalV2_1Doc))
    doc.vulnerabilities = [
      {
        metrics: [
          {
            products: ['P1'],
            content: {
              cvss_v2: { version: '2.0', baseScore: 4.3, vectorString: 'V2' },
            },
          },
        ],
      },
    ]
    const enriched = enrichDocumentV2_1(doc)
    const html = HTMLTemplate2_1(enriched)

    expect(html).toContain('CVSSv2.0 Base Score: 4.3')
    expect(html).not.toContain('CVSSv3.1 Base Score')
  })

  it('renders vulnerability-level legal_disclaimer notes', () => {
    const doc = /** @type {any} */ (structuredClone(minimalV2_1Doc))
    doc.vulnerabilities = [
      {
        title: 'Example vuln',
        notes: [
          {
            category: 'legal_disclaimer',
            title: 'Disclaimer',
            text: 'Vulnerability-level legal disclaimer text',
          },
        ],
      },
    ]
    const enriched = enrichDocumentV2_1(doc)
    const html = HTMLTemplate2_1(enriched)

    expect(html).toContain('Vulnerability-level legal disclaimer text')
  })
})

const renderV2_1 = (/** @type {(doc: any) => void} */ modify) => {
  const doc = /** @type {any} */ (structuredClone(minimalV2_1Doc))
  modify(doc)
  const { document: enriched } = enrichDocumentV2_1(doc)
  return HTMLTemplate2_1({ document: renderMarkdown(enriched) })
}

describe('HTMLTemplate2_1 (CSAF 2.1 specific content)', () => {
  describe('publisher contact', () => {
    it('renders all fields of the publisher contact object', () => {
      const html = renderV2_1((doc) => {
        doc.document.publisher.contact = {
          details: 'Call **us** anytime',
          email: 'psirt@example.com',
          url: 'https://example.com/contact',
          public_openpgp_key_url: 'https://example.com/key',
        }
      })

      expect(html).toContain('Call <strong>us</strong> anytime')
      expect(html).toContain('<a href="mailto:psirt@example.com">')
      expect(html).toContain('psirt@example.com</a>')
      expect(html).toContain(
        'href="https:&#x2F;&#x2F;example.com&#x2F;contact"',
      )
      expect(html).toContain('href="https:&#x2F;&#x2F;example.com&#x2F;key"')
    })

    it('renders a contact with only some fields set', () => {
      const html = renderV2_1((doc) => {
        doc.document.publisher.contact = { email: 'only@example.com' }
      })

      expect(html).toContain('only@example.com')
      expect(html).not.toContain('OpenPGP')
    })

    it('does not render the legacy contact_details property', () => {
      const html = renderV2_1((doc) => {
        doc.document.publisher.contact_details = 'LEGACY_DETAILS'
      })

      expect(html).not.toContain('LEGACY_DETAILS')
    })
  })

  it('renders license_expression', () => {
    const html = renderV2_1((doc) => {
      doc.document.license_expression = 'CC-BY-4.0'
    })

    expect(html).toContain('License expression: CC-BY-4.0')
  })

  it('does not render a license expression row when there is none', () => {
    expect(renderV2_1(() => {})).not.toContain('License expression')
  })

  describe('document.involvement', () => {
    /** @param {any} doc */
    const addInvolvement = (doc) => {
      doc.product_tree = {
        full_product_names: [{ product_id: 'P1', name: 'Product One' }],
        product_groups: [
          { group_id: 'G1', product_ids: ['P1'], summary: 'Group One' },
        ],
      }
      doc.document.involvement = {
        entities: [
          {
            entity_id: 'EID-1',
            name: 'Acme Inc',
            category: 'vendor',
            contact: { email: 'acme@example.com' },
          },
          { entity_id: 'EID-2', category: 'reporting_authority' },
        ],
        entity_groups: [
          {
            entity_group_id: 'EGID-1',
            name: 'Everyone',
            summary: 'All **involved** parties',
            entity_ids: ['EID-1', 'EID-2'],
          },
        ],
        actions: [
          {
            action_id: 'AID-1',
            category: 'fix_release',
            status: 'completed',
            date: '2024-03-03T00:00:00Z',
            acting_entity_refs: ['EID-1'],
            receiving_entity_refs: ['EGID-1'],
            dl_vuln_ids: ['DLV-1'],
            referenced_action_ids: ['AID-0'],
            product_ids: ['P1'],
            group_ids: ['G1'],
            summary: 'We **released** a fix',
          },
        ],
      }
    }

    it('renders entities, entity groups and actions with resolved names', () => {
      const html = renderV2_1(addInvolvement)

      expect(html).toContain('<h2>Involvement</h2>')
      expect(html).toContain('<b>Acme Inc</b> (vendor, EID-1)')
      expect(html).toContain('acme@example.com')
      // entity without a name falls back to its id
      expect(html).toContain('<b>EID-2</b> (reporting authority, EID-2)')
      expect(html).toContain('<b>Everyone</b> (EGID-1)')
      expect(html).toContain('All <strong>involved</strong> parties')
      expect(html).toContain('Members: Acme Inc, EID-2')
      expect(html).toContain('Fix release (completed, AID-1)')
      expect(html).toContain('By: Acme Inc')
      expect(html).toContain('To: Everyone')
      expect(html).toContain('Vulnerabilities: DLV-1')
      expect(html).toContain('Refers to actions: AID-0')
      expect(html).toContain('We <strong>released</strong> a fix')
      expect(html).toContain('<li>Product One</li>')
      expect(html).toContain('<li>Group One</li>')
    })

    it('renders nothing when there is no involvement', () => {
      expect(renderV2_1(() => {})).not.toContain('<h2>Involvement</h2>')
    })

    it('does not render the CSAF 2.0 vulnerability involvements', () => {
      const html = renderV2_1((doc) => {
        doc.vulnerabilities = [
          {
            title: 'V',
            involvements: [{ party: 'vendor', summary: 'LEGACY_INVOLVEMENT' }],
          },
        ]
      })

      expect(html).not.toContain('LEGACY_INVOLVEMENT')
      expect(html).not.toContain('<h4>Involvement</h4>')
    })
  })

  describe('note product_ids / group_ids', () => {
    it('renders the products and groups a document note and a vulnerability note apply to', () => {
      const html = renderV2_1((doc) => {
        doc.product_tree = {
          full_product_names: [{ product_id: 'P1', name: 'Product One' }],
          product_groups: [
            { group_id: 'G1', product_ids: ['P1'], summary: 'Group One' },
          ],
        }
        doc.document.notes = [
          { category: 'general', text: 'doc note', product_ids: ['P1'] },
        ]
        doc.vulnerabilities = [
          {
            title: 'V',
            notes: [
              { category: 'description', text: 'vuln note', group_ids: ['G1'] },
            ],
          },
        ]
      })

      expect(html).toContain('doc note')
      expect(html).toContain('<li>Product One</li>')
      expect(html).toContain('vuln note')
      expect(html).toContain('<li>Group One</li>')
    })

    it('renders notes without product_ids / group_ids unchanged', () => {
      const html = renderV2_1((doc) => {
        doc.document.notes = [{ category: 'general', text: 'plain note' }]
      })

      expect(html).toContain('plain note')
      expect(html).not.toContain('For products:')
      expect(html).not.toContain('For groups:')
    })
  })

  describe('product_tree.product_paths', () => {
    it('resolves product names defined only via a product path', () => {
      const html = renderV2_1((doc) => {
        doc.product_tree = {
          full_product_names: [{ product_id: 'P0', name: 'Base' }],
          product_paths: [
            {
              beginning_product_reference: 'P0',
              subpaths: [],
              full_product_name: { product_id: 'P1', name: 'Path Product' },
            },
          ],
        }
        doc.vulnerabilities = [
          { title: 'V', product_status: { known_not_affected: ['P1'] } },
        ]
      })

      expect(html).toContain('Path Product')
    })
  })

  describe('vulnerabilities', () => {
    it('renders the product_status "unknown" group', () => {
      const html = renderV2_1((doc) => {
        doc.product_tree = {
          full_product_names: [{ product_id: 'P1', name: 'Mystery Product' }],
        }
        doc.vulnerabilities = [
          { title: 'V', product_status: { unknown: ['P1'] } },
        ]
      })

      expect(html).toContain('<h5>Unknown</h5>')
      expect(html).toContain('Mystery Product')
    })

    it.each([
      ['fix_planned', 'Fix planned', 'FIX_PLANNED_DETAILS'],
      ['optional_patch', 'Optional patch', 'OPTIONAL_PATCH_DETAILS'],
    ])('renders %s remediations', (category, heading, details) => {
      const html = renderV2_1((doc) => {
        doc.vulnerabilities = [
          { title: 'V', remediations: [{ category, details }] },
        ]
      })

      expect(html).toContain('<h4>Remediations</h4>')
      expect(html).toContain(`<h5>${heading}`)
      expect(html).toContain(details)
    })

    it('renders first_known_exploitation_dates with their scope', () => {
      const html = renderV2_1((doc) => {
        doc.product_tree = {
          full_product_names: [{ product_id: 'P1', name: 'Exploited Product' }],
        }
        doc.vulnerabilities = [
          {
            title: 'V',
            first_known_exploitation_dates: [
              {
                exploitation_date: '2024-02-02T00:00:00Z',
                date: '2024-02-03T00:00:00Z',
                product_ids: ['P1'],
              },
            ],
          },
        ]
      })

      expect(html).toContain('First known exploitation dates')
      expect(html).toContain('2024-02-02T00:00:00Z')
      expect(html).toContain('information from 2024-02-03T00:00:00Z')
      expect(html).toContain('<li>Exploited Product</li>')
    })

    it('renders the document-local vulnerability id', () => {
      const html = renderV2_1((doc) => {
        doc.vulnerabilities = [{ title: 'V', dl_vuln_id: 'DLV-42' }]
      })

      expect(html).toContain('Document-local ID:')
      expect(html).toContain('DLV-42')
    })

    it('renders the product/group scope of vulnerability ids', () => {
      const html = renderV2_1((doc) => {
        doc.product_tree = {
          full_product_names: [{ product_id: 'P1', name: 'Scoped Product' }],
        }
        doc.vulnerabilities = [
          {
            title: 'V',
            ids: [
              {
                system_name: 'Bug Tracker',
                text: 'BUG-1',
                product_ids: ['P1'],
              },
              { system_name: 'Other', text: 'GLOBAL-ID' },
            ],
          },
        ]
      })

      expect(html).toContain('<h4>Scoped IDs</h4>')
      expect(html).toContain('BUG-1 (Bug Tracker)')
      expect(html).toContain('<li>Scoped Product</li>')
      // ids without a scope are not part of this block
      expect(html).not.toContain('GLOBAL-ID')
    })

    it('renders epss, qualitative severity rating and ssvc_v2 metrics', () => {
      const html = renderV2_1((doc) => {
        doc.product_tree = {
          full_product_names: [{ product_id: 'P1', name: 'Rated Product' }],
        }
        doc.vulnerabilities = [
          {
            title: 'V',
            metrics: [
              {
                products: ['P1'],
                source: 'https://example.com/source',
                content: {
                  qualitative_severity_rating: 'high',
                  epss: {
                    probability: '0.12',
                    percentile: '0.85',
                    timestamp: '2024-01-01T00:00:00Z',
                  },
                  ssvc_v2: {
                    timestamp: '2024-01-02T00:00:00Z',
                    schemaVersion: '2.0.0',
                    selections: [
                      {
                        namespace: 'ssvc',
                        key: 'E',
                        version: '1.1.0',
                        name: 'Exploitation',
                        values: [{ key: 'P', name: 'PoC' }, { key: 'A' }],
                      },
                    ],
                  },
                },
              },
            ],
          },
        ]
      })

      expect(html).toContain('<h4>Metrics</h4>')
      expect(html).toContain('Qualitative severity rating: High')
      expect(html).toContain('EPSS: probability 0.12, percentile 0.85')
      expect(html).toContain('Exploitation: PoC, A')
      expect(html).toContain('For products: Rated Product')
      expect(html).toContain('href="https:&#x2F;&#x2F;example.com&#x2F;source"')
    })

    it('does not render a metrics section for CVSS-only metrics', () => {
      const html = renderV2_1((doc) => {
        doc.vulnerabilities = [
          {
            title: 'V',
            metrics: [
              {
                products: ['P1'],
                content: {
                  cvss_v3: { version: '3.1', baseScore: 5, vectorString: 'V' },
                },
              },
            ],
          },
        ]
      })

      expect(html).not.toContain('<h4>Metrics</h4>')
    })
  })

  it('renders the CSAF 2.1 TLP labels and sharing group', () => {
    const html = renderV2_1((doc) => {
      doc.document.distribution = {
        tlp: { label: 'AMBER+STRICT' },
        sharing_group: { id: 'SG-ID', name: 'SG Name' },
      }
    })

    expect(html).toContain('TLP:AMBER+STRICT')
    expect(html).toContain('Name: SG Name')
  })
})
