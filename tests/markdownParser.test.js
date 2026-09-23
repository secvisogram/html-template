import { describe, expect, it } from 'vitest'
import { renderMarkdown } from '../lib/markdownParser.js'

describe('renderMarkdown', () => {
  it('leaves plain text (no markdown syntax) unwrapped and unchanged', () => {
    const doc = { document: { distribution: { text: 'plain text' } } }
    renderMarkdown(doc)
    expect(doc.document.distribution.text).toBe('plain text')
  })

  it('leaves multi-line plain text (no markdown syntax) unwrapped and unchanged', () => {
    // Regression test: without the `s` (dotAll) flag, `.` in the
    // "was markdown actually used" detection regex doesn't match newlines,
    // so this never matched at all for multi-line text - even though
    // micromark, like any other plain text, still wraps it in a single
    // <p> tag - and the wrapped version was incorrectly returned instead
    // of the original plain text.
    const doc = { document: { distribution: { text: 'line1\nline2' } } }
    renderMarkdown(doc)
    expect(doc.document.distribution.text).toBe('line1\nline2')
  })

  it('renders bold markdown syntax to HTML', () => {
    const doc = { document: { distribution: { text: '**bold** text' } } }
    renderMarkdown(doc)
    expect(doc.document.distribution.text).toBe(
      '<p><strong>bold</strong> text</p>',
    )
  })

  it('renders a markdown list to an HTML list', () => {
    const doc = {
      document: { distribution: { text: '- item 1\n- item 2' } },
    }
    renderMarkdown(doc)
    expect(doc.document.distribution.text).toBe(
      '<ul>\n<li>item 1</li>\n<li>item 2</li>\n</ul>',
    )
  })

  it('renders GFM strikethrough (a GitHub Flavored Markdown extension)', () => {
    const doc = { document: { distribution: { text: '~~struck~~' } } }
    renderMarkdown(doc)
    expect(doc.document.distribution.text).toBe('<p><del>struck</del></p>')
  })

  it('leaves a field not on the markdown allow-list untouched, even with markdown syntax', () => {
    const doc = { document: { category: '**not markdown-parsed**' } }
    renderMarkdown(doc)
    expect(doc.document.category).toBe('**not markdown-parsed**')
  })

  it('does nothing when the field is absent', () => {
    const doc = { document: /** @type {any} */ ({}) }
    expect(() => renderMarkdown(doc)).not.toThrow()
    expect(doc.document.distribution).toBeUndefined()
  })

  it('applies markdown rendering across every entry of a wildcard array field', () => {
    const doc = {
      document: {
        notes: [{ text: 'plain' }, { text: '**bold**' }],
      },
    }
    renderMarkdown(doc)
    expect(doc.document.notes[0].text).toBe('plain')
    expect(doc.document.notes[1].text).toBe('<p><strong>bold</strong></p>')
  })

  it('applies markdown rendering to a nested wildcard array field (array of arrays)', () => {
    const doc = {
      vulnerabilities: [
        {
          remediations: [{ entitlements: ['plain', '**bold**'] }],
        },
      ],
    }
    renderMarkdown(doc)
    expect(doc.vulnerabilities[0].remediations[0].entitlements).toEqual([
      'plain',
      '<p><strong>bold</strong></p>',
    ])
  })

  it('applies markdown rendering to a triple-nested wildcard array field (vulnerabilities.*.remediations.*.group_ids.*.name)', () => {
    const doc = {
      vulnerabilities: [
        {
          remediations: [{ group_ids: [{ id: 'G1', name: '**bold**' }] }],
        },
      ],
    }
    renderMarkdown(doc)
    expect(doc.vulnerabilities[0].remediations[0].group_ids[0].name).toBe(
      '<p><strong>bold</strong></p>',
    )
  })

  it('applies markdown rendering to vulnerabilities.*.threats.*.group_ids.*.name', () => {
    const doc = {
      vulnerabilities: [
        {
          threats: [{ group_ids: [{ id: 'G1', name: '**bold**' }] }],
        },
      ],
    }
    renderMarkdown(doc)
    expect(doc.vulnerabilities[0].threats[0].group_ids[0].name).toBe(
      '<p><strong>bold</strong></p>',
    )
  })

  it('returns the same document instance it was given (mutates in place)', () => {
    const doc = { document: { distribution: { text: 'plain' } } }
    expect(renderMarkdown(doc)).toBe(doc)
  })
})
