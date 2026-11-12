import { describe, expect, it } from 'vitest'
import {
  enrichDocumentV2_0,
  enrichDocumentV2_1,
} from '../lib/enrichDocument.js'

describe('enrichDocumentV2_0', () => {
  it('does not mutate the original input document', () => {
    const doc = { document: {}, vulnerabilities: [] }
    enrichDocumentV2_0(doc)
    expect(doc).toEqual({ document: {}, vulnerabilities: [] })
  })

  it('attaches the mustache lambda helpers to the returned document', () => {
    const { document } = enrichDocumentV2_0({ document: {} })
    expect(document.removeTrailingComma).toBeTypeOf('function')
    expect(document.upperCase).toBeTypeOf('function')
    expect(document.replaceUnderscores).toBeTypeOf('function')
    expect(document.secureHref).toBeTypeOf('function')
  })

  describe('max_base_score', () => {
    it('is the highest cvss_v3 baseScore across all vulnerabilities/scores', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        vulnerabilities: [
          { scores: [{ cvss_v3: { baseScore: 4.3 } }] },
          {
            scores: [
              { cvss_v3: { baseScore: 7.5 } },
              { cvss_v3: { baseScore: 9.8 } },
            ],
          },
        ],
      })
      expect(document.document.max_base_score).toBe('9.8')
    })

    it('is "0" when there are no vulnerabilities', () => {
      const { document } = enrichDocumentV2_0({ document: {} })
      expect(document.document.max_base_score).toBe('0')
    })
  })

  describe('document notes categorisation', () => {
    it('buckets notes by category and defaults unknown categories to notes_unknown', () => {
      const { document } = enrichDocumentV2_0({
        document: {
          notes: [
            { category: 'summary', text: 'a' },
            { category: 'details', text: 'b' },
            { category: 'made_up_category', text: 'c' },
          ],
        },
      })
      expect(document.document.notes_summary).toEqual([
        { category: 'summary', text: 'a' },
      ])
      expect(document.document.notes_details).toEqual([
        { category: 'details', text: 'b' },
      ])
      expect(document.document.notes_unknown).toEqual([
        { category: 'made_up_category', text: 'c' },
      ])
      expect(document.document.notes_general).toEqual([])
    })
  })

  describe('product tree enrichment', () => {
    it('resolves product names for product_groups from full_product_names', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        product_tree: {
          full_product_names: [{ product_id: 'P1', name: 'Product One' }],
          product_groups: [{ group_id: 'G1', product_ids: ['P1', 'P2'] }],
        },
      })
      expect(document.product_tree.product_groups[0].product_ids).toEqual([
        { id: 'P1', name: 'Product One' },
        { id: 'P2', name: '' },
      ])
    })

    it('resolves product names for products nested inside branches', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        product_tree: {
          branches: [
            {
              branches: [
                { product: { product_id: 'P1', name: 'Nested Product' } },
              ],
            },
          ],
          product_groups: [{ group_id: 'G1', product_ids: ['P1'] }],
        },
      })
      expect(document.product_tree.product_groups[0].product_ids).toEqual([
        { id: 'P1', name: 'Nested Product' },
      ])
    })

    it('resolves product names for products defined via relationships', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        product_tree: {
          relationships: [
            {
              full_product_name: { product_id: 'P1', name: 'Related Product' },
            },
          ],
          product_groups: [{ group_id: 'G1', product_ids: ['P1'] }],
        },
      })
      expect(document.product_tree.product_groups[0].product_ids).toEqual([
        { id: 'P1', name: 'Related Product' },
      ])
    })

    it('uses the first matching entry when a product_id is defined more than once (invalid but possible CSAF document)', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        product_tree: {
          full_product_names: [
            { product_id: 'P1', name: 'First Definition' },
            { product_id: 'P1', name: 'Second Definition' },
          ],
          product_groups: [{ group_id: 'G1', product_ids: ['P1'] }],
        },
      })
      expect(document.product_tree.product_groups[0].product_ids).toEqual([
        { id: 'P1', name: 'First Definition' },
      ])
    })
  })

  describe('vulnerability product_status enrichment', () => {
    it('resolves product names and CVSS data for product_status entries', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        product_tree: {
          full_product_names: [{ product_id: 'P1', name: 'Product One' }],
        },
        vulnerabilities: [
          {
            scores: [
              {
                products: ['P1'],
                cvss_v3: { baseScore: 7.5, vectorString: 'VEC-STRING' },
              },
            ],
            product_status: { known_affected: ['P1'] },
          },
        ],
      })
      expect(document.vulnerabilities[0].product_status.known_affected).toEqual(
        [
          {
            id: 'P1',
            name: 'Product One',
            vectorString: 'VEC-STRING',
            baseScore: 7.5,
          },
        ],
      )
    })

    it('falls back to just id/name (no CVSS data) when the product has no score entry', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        product_tree: {
          full_product_names: [{ product_id: 'P1', name: 'Product One' }],
        },
        vulnerabilities: [
          {
            product_status: { fixed: ['P1'] },
          },
        ],
      })
      expect(document.vulnerabilities[0].product_status.fixed).toEqual([
        { id: 'P1', name: 'Product One' },
      ])
    })

    it('attaches matching flag labels to known_not_affected entries', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        product_tree: {
          full_product_names: [{ product_id: 'P1', name: 'Product One' }],
        },
        vulnerabilities: [
          {
            product_status: { known_not_affected: ['P1'] },
            flags: [
              {
                label: 'vulnerable_code_not_present',
                product_ids: ['P1'],
              },
            ],
          },
        ],
      })
      expect(
        document.vulnerabilities[0].product_status.known_not_affected[0].flags,
      ).toEqual(['vulnerable_code_not_present'])
    })

    it('attaches flags to known_not_affected entries reached only via a group_id', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        product_tree: {
          full_product_names: [{ product_id: 'P1', name: 'Product One' }],
          product_groups: [{ group_id: 'G1', product_ids: ['P1'] }],
        },
        vulnerabilities: [
          {
            product_status: { known_not_affected: ['P1'] },
            flags: [{ label: 'component_not_present', group_ids: ['G1'] }],
          },
        ],
      })
      expect(
        document.vulnerabilities[0].product_status.known_not_affected[0].flags,
      ).toEqual(['component_not_present'])
    })
  })

  describe('remediations enrichment', () => {
    it('buckets remediations by category', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        vulnerabilities: [
          {
            remediations: [
              { category: 'vendor_fix', date: '2024-01-01' },
              { category: 'workaround', date: '2024-01-01' },
            ],
          },
        ],
      })
      expect(document.vulnerabilities[0].remediations_vendor_fix).toHaveLength(
        1,
      )
      expect(document.vulnerabilities[0].remediations_workaround).toHaveLength(
        1,
      )
      expect(document.vulnerabilities[0].remediations_mitigation).toEqual([])
    })

    it('buckets the CSAF 2.1 categories fix_planned and optional_patch instead of treating them as unknown', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        vulnerabilities: [
          {
            remediations: [
              { category: 'fix_planned', details: 'a' },
              { category: 'optional_patch', details: 'b' },
              { category: 'made_up', details: 'c' },
            ],
          },
        ],
      })
      const vulnerability = document.vulnerabilities[0]
      expect(vulnerability.remediations_fix_planned).toHaveLength(1)
      expect(vulnerability.remediations_optional_patch).toHaveLength(1)
      expect(vulnerability.remediations_unknown).toHaveLength(1)
    })

    it('sorts remediations within a category by date, most recent first', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        vulnerabilities: [
          {
            remediations: [
              { category: 'vendor_fix', date: '2024-01-01' },
              { category: 'vendor_fix', date: '2025-06-01' },
            ],
          },
        ],
      })
      expect(
        document.vulnerabilities[0].remediations_vendor_fix.map(
          (/** @type {any} */ r) => r.date,
        ),
      ).toEqual(['2025-06-01', '2024-01-01'])
    })

    it('sorts undated remediations after dated ones', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        vulnerabilities: [
          {
            remediations: [
              { category: 'vendor_fix', date: '2024-01-01' },
              { category: 'vendor_fix' },
            ],
          },
        ],
      })
      expect(
        document.vulnerabilities[0].remediations_vendor_fix.map(
          (/** @type {any} */ r) => r.date,
        ),
      ).toEqual(['2024-01-01', undefined])
    })

    it('keeps dated remediations correctly sorted even when multiple undated ones are also present', () => {
      // Regression test: comparing two dateless entries used to compute
      // new Date(undefined).getTime() - new Date(undefined).getTime(),
      // i.e. NaN - NaN = NaN, an invalid sort comparator result that could
      // produce an unstable/incorrect overall order (verified: it did,
      // e.g. moving the most recent dated entry to the end instead of the
      // start), rather than just leaving the two dateless entries adjacent.
      const { document } = enrichDocumentV2_0({
        document: {},
        vulnerabilities: [
          {
            remediations: [
              { category: 'vendor_fix' },
              { category: 'vendor_fix', date: '2024-01-01' },
              { category: 'vendor_fix' },
              { category: 'vendor_fix', date: '2025-06-01' },
            ],
          },
        ],
      })
      expect(
        document.vulnerabilities[0].remediations_vendor_fix.map(
          (/** @type {any} */ r) => r.date,
        ),
      ).toEqual(['2025-06-01', '2024-01-01', undefined, undefined])
    })

    it('resolves product_ids and group_ids to id/name pairs on each remediation', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        product_tree: {
          full_product_names: [{ product_id: 'P1', name: 'Product One' }],
          product_groups: [{ group_id: 'G1', summary: 'Group One' }],
        },
        vulnerabilities: [
          {
            remediations: [
              {
                category: 'vendor_fix',
                product_ids: ['P1'],
                group_ids: ['G1'],
              },
            ],
          },
        ],
      })
      const remediation = document.vulnerabilities[0].remediations_vendor_fix[0]
      expect(remediation.product_ids).toEqual([
        { id: 'P1', name: 'Product One' },
      ])
      expect(remediation.group_ids).toEqual([{ id: 'G1', name: 'Group One' }])
    })
  })

  describe('threats enrichment', () => {
    it('buckets threats by category', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        vulnerabilities: [
          {
            threats: [
              { category: 'impact' },
              { category: 'exploit_status' },
              { category: 'target_set' },
              { category: 'made_up' },
            ],
          },
        ],
      })
      expect(document.vulnerabilities[0].threats_impact).toHaveLength(1)
      expect(document.vulnerabilities[0].threats_exploit_status).toHaveLength(1)
      expect(document.vulnerabilities[0].threats_target_set).toHaveLength(1)
      expect(document.vulnerabilities[0].threats_unknown).toHaveLength(1)
    })
  })

  describe('vulnerability notes categorisation', () => {
    it('buckets vulnerability notes by category', () => {
      const { document } = enrichDocumentV2_0({
        document: {},
        vulnerabilities: [
          {
            notes: [
              { category: 'general', text: 'a' },
              { category: 'other', text: 'b' },
            ],
          },
        ],
      })
      expect(document.vulnerabilities[0].notes_general).toEqual([
        { category: 'general', text: 'a' },
      ])
      expect(document.vulnerabilities[0].notes_other).toEqual([
        { category: 'other', text: 'b' },
      ])
    })
  })
})

describe('enrichDocumentV2_1', () => {
  it('reads CVSS data from vulnerability.metrics[].content.cvss_v3 rather than scores', () => {
    const { document } = enrichDocumentV2_1({
      document: {},
      vulnerabilities: [
        {
          metrics: [
            {
              products: ['P1'],
              content: {
                cvss_v3: {
                  version: '3.1',
                  baseScore: 9.8,
                  vectorString: 'VEC',
                },
              },
            },
          ],
          product_status: { known_affected: ['P1'] },
        },
      ],
    })
    expect(document.document.max_base_score).toBe('9.8')
    expect(document.vulnerabilities[0].product_status.known_affected).toEqual([
      {
        id: 'P1',
        name: '',
        vectorString: 'VEC',
        baseScore: 9.8,
        cvssVersion: '3.1',
      },
    ])
  })

  it('attaches the mustache lambda helpers to the returned document', () => {
    const { document } = enrichDocumentV2_1({ document: {} })
    expect(document.removeTrailingComma).toBeTypeOf('function')
    expect(document.secureHref).toBeTypeOf('function')
  })

  it('resolves product names from full_product_names, both in product_tree and product_status', () => {
    const { document } = enrichDocumentV2_1({
      document: {},
      product_tree: {
        full_product_names: [{ product_id: 'P1', name: 'Product One' }],
        product_groups: [{ group_id: 'G1', product_ids: ['P1'] }],
      },
      vulnerabilities: [
        {
          metrics: [
            {
              products: ['P1'],
              content: {
                cvss_v3: { version: '3.1', baseScore: 5.0, vectorString: 'V' },
              },
            },
          ],
          product_status: { known_affected: ['P1'] },
        },
      ],
    })
    expect(document.product_tree.product_groups[0].product_ids).toEqual([
      { id: 'P1', name: 'Product One' },
    ])
    expect(document.vulnerabilities[0].product_status.known_affected).toEqual([
      {
        id: 'P1',
        name: 'Product One',
        vectorString: 'V',
        baseScore: 5,
        cvssVersion: '3.1',
      },
    ])
  })

  describe('CVSS version selection (v2/v3/v4 on the same metric)', () => {
    it('reads baseScore/vectorString/version from cvss_v2 when it is the only version present', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        vulnerabilities: [
          {
            metrics: [
              {
                products: ['P1'],
                content: {
                  cvss_v2: {
                    version: '2.0',
                    baseScore: 4.3,
                    vectorString: 'VEC2',
                  },
                },
              },
            ],
            product_status: { known_affected: ['P1'] },
          },
        ],
      })
      expect(document.vulnerabilities[0].product_status.known_affected).toEqual(
        [
          {
            id: 'P1',
            name: '',
            vectorString: 'VEC2',
            baseScore: 4.3,
            cvssVersion: '2.0',
          },
        ],
      )
      expect(document.document.max_base_score).toBe('4.3')
    })

    it('reads cvss_v4 when it is the only version present', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        vulnerabilities: [
          {
            metrics: [
              {
                products: ['P1'],
                content: {
                  cvss_v4: {
                    version: '4.0',
                    baseScore: 9.8,
                    vectorString: 'VEC4',
                  },
                },
              },
            ],
            product_status: { known_affected: ['P1'] },
          },
        ],
      })
      expect(document.vulnerabilities[0].product_status.known_affected).toEqual(
        [
          {
            id: 'P1',
            name: '',
            vectorString: 'VEC4',
            baseScore: 9.8,
            cvssVersion: '4.0',
          },
        ],
      )
      expect(document.document.max_base_score).toBe('9.8')
    })

    it('prefers cvss_v4 over cvss_v3 and cvss_v2 when multiple are present on the same metric', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        vulnerabilities: [
          {
            metrics: [
              {
                products: ['P1'],
                content: {
                  cvss_v2: {
                    version: '2.0',
                    baseScore: 2.1,
                    vectorString: 'VEC2',
                  },
                  cvss_v3: {
                    version: '3.1',
                    baseScore: 5.0,
                    vectorString: 'VEC3',
                  },
                  cvss_v4: {
                    version: '4.0',
                    baseScore: 9.8,
                    vectorString: 'VEC4',
                  },
                },
              },
            ],
            product_status: { known_affected: ['P1'] },
          },
        ],
      })
      expect(document.vulnerabilities[0].product_status.known_affected).toEqual(
        [
          {
            id: 'P1',
            name: '',
            vectorString: 'VEC4',
            baseScore: 9.8,
            cvssVersion: '4.0',
          },
        ],
      )
    })

    it('prefers cvss_v3 over cvss_v2 when both are present but cvss_v4 is absent', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        vulnerabilities: [
          {
            metrics: [
              {
                products: ['P1'],
                content: {
                  cvss_v2: {
                    version: '2.0',
                    baseScore: 2.1,
                    vectorString: 'VEC2',
                  },
                  cvss_v3: {
                    version: '3.1',
                    baseScore: 5.0,
                    vectorString: 'VEC3',
                  },
                },
              },
            ],
            product_status: { known_affected: ['P1'] },
          },
        ],
      })
      expect(document.vulnerabilities[0].product_status.known_affected).toEqual(
        [
          {
            id: 'P1',
            name: '',
            vectorString: 'VEC3',
            baseScore: 5,
            cvssVersion: '3.1',
          },
        ],
      )
    })

    it('computes max_base_score across different CVSS versions used by different metrics', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        vulnerabilities: [
          {
            metrics: [
              {
                products: ['P1'],
                content: {
                  cvss_v2: {
                    version: '2.0',
                    baseScore: 10,
                    vectorString: 'VEC2',
                  },
                },
              },
              {
                products: ['P2'],
                content: {
                  cvss_v4: {
                    version: '4.0',
                    baseScore: 6.5,
                    vectorString: 'VEC4',
                  },
                },
              },
            ],
          },
        ],
      })
      // Highest baseScore across metrics wins, regardless of which CVSS
      // version each individual metric happens to use.
      expect(document.document.max_base_score).toBe('10')
      // The label must reflect whichever CVSS version actually produced the
      // winning score (v2 here), not always "CVSSv3.1" as it used to be
      // hardcoded regardless of the real underlying CVSS version.
      expect(document.document.max_base_score_cvss_label).toBe('CVSSv2.0')
    })
  })

  describe('max_base_score_cvss_label', () => {
    it('is "CVSS" (no version suffix) when there are no scores at all', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        vulnerabilities: [],
      })
      expect(document.document.max_base_score_cvss_label).toBe('CVSS')
    })

    it('reflects CVSS v3 when that is the winning score', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        vulnerabilities: [
          {
            metrics: [
              {
                products: ['P1'],
                content: {
                  cvss_v3: {
                    version: '3.1',
                    baseScore: 5.0,
                    vectorString: 'VEC3',
                  },
                },
              },
            ],
          },
        ],
      })
      expect(document.document.max_base_score_cvss_label).toBe('CVSSv3.1')
    })

    it('reflects CVSS v4 when that is the winning score', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        vulnerabilities: [
          {
            metrics: [
              {
                products: ['P1'],
                content: {
                  cvss_v4: {
                    version: '4.0',
                    baseScore: 9.8,
                    vectorString: 'VEC4',
                  },
                },
              },
            ],
          },
        ],
      })
      expect(document.document.max_base_score_cvss_label).toBe('CVSSv4.0')
    })
  })

  describe('product_paths', () => {
    it('indexes products defined in product_tree.product_paths', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        product_tree: {
          product_groups: [{ group_id: 'G1', product_ids: ['P2'] }],
          product_paths: [
            {
              beginning_product_reference: 'P1',
              subpaths: [],
              full_product_name: { product_id: 'P2', name: 'Path Product' },
            },
          ],
        },
      })
      expect(document.product_tree.product_groups[0].product_ids).toEqual([
        { id: 'P2', name: 'Path Product' },
      ])
    })
  })

  describe('product_status.unknown', () => {
    it('resolves product names and CVSS data for the unknown group', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        product_tree: {
          full_product_names: [{ product_id: 'P1', name: 'Product One' }],
        },
        vulnerabilities: [
          {
            metrics: [
              {
                products: ['P1'],
                content: {
                  cvss_v3: {
                    version: '3.1',
                    baseScore: 5,
                    vectorString: 'VEC',
                  },
                },
              },
            ],
            product_status: { unknown: ['P1'] },
          },
        ],
      })
      expect(document.vulnerabilities[0].product_status.unknown).toEqual([
        {
          id: 'P1',
          name: 'Product One',
          vectorString: 'VEC',
          baseScore: 5,
          cvssVersion: '3.1',
        },
      ])
    })
  })

  describe('product_ids / group_ids on notes, ids and first_known_exploitation_dates', () => {
    const productTree = {
      full_product_names: [{ product_id: 'P1', name: 'Product One' }],
      product_groups: [{ group_id: 'G1', product_ids: ['P1'], summary: 'S1' }],
    }

    it('resolves them to id/name pairs', () => {
      const { document } = enrichDocumentV2_1({
        document: { notes: [{ category: 'general', product_ids: ['P1'] }] },
        product_tree: productTree,
        vulnerabilities: [
          {
            notes: [{ category: 'general', group_ids: ['G1'] }],
            ids: [{ system_name: 'S', text: 'T', product_ids: ['P1'] }],
            first_known_exploitation_dates: [
              { date: 'd', exploitation_date: 'e', group_ids: ['G1'] },
            ],
          },
        ],
      })
      const vulnerability = document.vulnerabilities[0]
      expect(document.document.notes_general[0].product_ids).toEqual([
        { id: 'P1', name: 'Product One' },
      ])
      expect(vulnerability.notes_general[0].group_ids).toEqual([
        { id: 'G1', name: 'S1' },
      ])
      expect(vulnerability.ids[0].product_ids).toEqual([
        { id: 'P1', name: 'Product One' },
      ])
      expect(vulnerability.first_known_exploitation_dates[0].group_ids).toEqual(
        [{ id: 'G1', name: 'S1' }],
      )
    })

    it('only collects ids that are scoped to products or groups in ids_scoped', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        product_tree: productTree,
        vulnerabilities: [
          {
            ids: [
              { system_name: 'S', text: 'scoped', product_ids: ['P1'] },
              { system_name: 'S', text: 'global' },
            ],
          },
        ],
      })
      expect(
        document.vulnerabilities[0].ids_scoped.map(
          (/** @type {any} */ id) => id.text,
        ),
      ).toEqual(['scoped'])
    })

    it('leaves notes without product_ids/group_ids untouched', () => {
      const note = { category: 'general', text: 'a' }
      const { document } = enrichDocumentV2_1({
        document: { notes: [note] },
      })
      expect(document.document.notes_general[0]).toEqual(note)
    })
  })

  describe('document.involvement', () => {
    it('resolves entity refs to names, falling back to the id, and resolves action scopes', () => {
      const { document } = enrichDocumentV2_1({
        document: {
          involvement: {
            entities: [
              { entity_id: 'EID-1', name: 'Acme', category: 'vendor' },
              { entity_id: 'EID-2', category: 'user' },
            ],
            entity_groups: [
              {
                entity_group_id: 'EGID-1',
                name: 'Group',
                entity_ids: ['EID-1', 'EID-2'],
              },
            ],
            actions: [
              {
                action_id: 'A1',
                category: 'fix_release',
                status: 'completed',
                date: 'd',
                acting_entity_refs: ['EID-1'],
                receiving_entity_refs: ['EGID-1', 'EID-unknown'],
                product_ids: ['P1'],
              },
            ],
          },
        },
        product_tree: {
          full_product_names: [{ product_id: 'P1', name: 'Product One' }],
        },
      })
      const involvement = document.document.involvement
      expect(
        involvement.entities.map((/** @type {any} */ e) => e.display_name),
      ).toEqual(['Acme', 'EID-2'])
      expect(involvement.entity_groups[0].entity_ids).toEqual([
        { id: 'EID-1', name: 'Acme' },
        { id: 'EID-2', name: 'EID-2' },
      ])
      const action = involvement.actions[0]
      expect(action.acting_entity_refs).toEqual([{ id: 'EID-1', name: 'Acme' }])
      expect(action.receiving_entity_refs).toEqual([
        { id: 'EGID-1', name: 'Group' },
        { id: 'EID-unknown', name: 'EID-unknown' },
      ])
      expect(action.product_ids).toEqual([{ id: 'P1', name: 'Product One' }])
    })

    it('leaves a document without involvement untouched', () => {
      const { document } = enrichDocumentV2_1({ document: {} })
      expect(document.document.involvement).toBeUndefined()
    })
  })

  describe('metrics_details', () => {
    it('collects epss, qualitative severity rating and a condensed ssvc_v2 selection list', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        product_tree: {
          full_product_names: [{ product_id: 'P1', name: 'Product One' }],
        },
        vulnerabilities: [
          {
            metrics: [
              {
                products: ['P1', 'P-unknown'],
                source: 'https://example.com',
                content: {
                  qualitative_severity_rating: 'low',
                  epss: { probability: '1', percentile: '2', timestamp: 't' },
                  ssvc_v2: {
                    timestamp: 'ts',
                    selections: [
                      {
                        namespace: 'ssvc',
                        key: 'KEY',
                        version: '1.0.0',
                        values: [{ key: 'V1' }, { key: 'V2', name: 'Two' }],
                      },
                    ],
                  },
                },
              },
            ],
          },
        ],
      })
      expect(document.vulnerabilities[0].metrics_details).toEqual([
        {
          products: [
            { id: 'P1', name: 'Product One' },
            { id: 'P-unknown', name: 'P-unknown' },
          ],
          source: 'https://example.com',
          qualitative_severity_rating: 'low',
          epss: { probability: '1', percentile: '2', timestamp: 't' },
          ssvc: {
            timestamp: 'ts',
            selections: [
              {
                label: 'KEY',
                namespace: 'ssvc',
                version: '1.0.0',
                values: 'V1, Two',
              },
            ],
          },
        },
      ])
    })

    it('skips metrics that only carry CVSS data', () => {
      const { document } = enrichDocumentV2_1({
        document: {},
        vulnerabilities: [
          {
            metrics: [
              {
                products: ['P1'],
                content: { cvss_v3: { version: '3.1', baseScore: 1 } },
              },
            ],
          },
        ],
      })
      expect(document.vulnerabilities[0].metrics_details).toEqual([])
    })
  })
})

describe('enrichDocumentV2_0 does not add CSAF 2.1-only attributes', () => {
  it('adds no metrics_details, ids_scoped or involvement handling', () => {
    const { document } = enrichDocumentV2_0({
      document: {},
      vulnerabilities: [{ title: 'V' }],
    })
    expect(document.vulnerabilities[0].metrics_details).toBeUndefined()
    expect(document.vulnerabilities[0].ids_scoped).toBeUndefined()
  })
})
