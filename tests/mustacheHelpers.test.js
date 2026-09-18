import { describe, expect, it } from 'vitest'
import {
  removeTrailingComma,
  replaceUnderscores,
  secureHref,
  upperCase,
} from '../lib/mustacheHelpers.js'

/**
 * Mustache calls a section lambda with the raw (unrendered) template text
 * and a `render` function that resolves `{{...}}` tags against the current
 * context, HTML-escaping the result exactly as Mustache's default
 * (non-triple-brace) interpolation does (mirrors Mustache.js's internal
 * `entityMap`). `secureHref` relies on this escaping — e.g. it matches its
 * `validMimeTypes` allow-list against an escaped `/`, and un-escapes `=`
 * before checking the base64 payload — so tests stub `render` with a
 * faithful reproduction of it rather than the identity function.
 *
 * @param {string} text
 */
const identityRender = (text) =>
  text.replace(
    /[&<>"'`=/]/g,
    (chr) =>
      ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
        '`': '&#x60;',
        '=': '&#x3D;',
        '/': '&#x2F;',
      })[chr] ?? chr,
  )

describe('removeTrailingComma', () => {
  it('removes the last comma from the rendered text', () => {
    const lambda = removeTrailingComma()
    expect(lambda('a, b, c, ', identityRender)).toBe('a, b, c')
  })

  it('returns the text unchanged when there is no comma', () => {
    const lambda = removeTrailingComma()
    expect(lambda('a single value', identityRender)).toBe('a single value')
  })

  it('does not strip a comma that is the very first character', () => {
    const lambda = removeTrailingComma()
    expect(lambda(',leading comma', identityRender)).toBe(',leading comma')
  })
})

describe('upperCase', () => {
  it('capitalises the first character', () => {
    const lambda = upperCase()
    expect(lambda('vendor_fix', identityRender)).toBe('Vendor_fix')
  })

  it('leaves an already-capitalised string unchanged', () => {
    const lambda = upperCase()
    expect(lambda('Already', identityRender)).toBe('Already')
  })
})

describe('replaceUnderscores', () => {
  it('replaces all underscores with spaces', () => {
    const lambda = replaceUnderscores()
    expect(lambda('vendor_fix_no_fix_planned', identityRender)).toBe(
      'vendor fix no fix planned',
    )
  })

  it('leaves text without underscores unchanged', () => {
    const lambda = replaceUnderscores()
    expect(lambda('no underscores here', identityRender)).toBe(
      'no underscores here',
    )
  })
})

describe('secureHref', () => {
  // Expected values are HTML-escaped (e.g. `/` -> `&#x2F;`, `=` -> `&#x3D;`)
  // because `render(text)` inside the lambda applies the same escaping
  // Mustache's default `{{...}}` interpolation would - this is what actually
  // ends up in the rendered HTML output too. It's valid HTML; browsers
  // decode entities in attribute values when parsing.
  it.each([
    ['#fragment', 'href="#fragment"'],
    ['mailto:test@example.com', 'href="mailto:test@example.com"'],
    ['tel:+123456789', 'href="tel:+123456789"'],
    ['http://example.com', 'href="http:&#x2F;&#x2F;example.com"'],
    ['https://example.com', 'href="https:&#x2F;&#x2F;example.com"'],
    ['ftp://example.com/file', 'href="ftp:&#x2F;&#x2F;example.com&#x2F;file"'],
  ])('accepts allow-listed scheme %s', (href, expected) => {
    const lambda = secureHref()
    expect(lambda(href, identityRender)).toBe(expected)
  })

  it.each([
    ['javascript:alert(1)'],
    ['data:text/html,<script>alert(1)</script>'],
    ['vbscript:msgbox(1)'],
  ])('rejects disallowed scheme %s', (href) => {
    const lambda = secureHref()
    expect(lambda(href, identityRender)).toBe('')
  })

  it('accepts a valid base64-encoded PNG data URI', () => {
    const lambda = secureHref()
    // "QUJD" (base64 for "ABC") is valid base64; content doesn't matter here.
    const href = 'data:image/png;base64,QUJD'
    expect(lambda(href, identityRender)).toBe(
      'href="data:image&#x2F;png;base64,QUJD"',
    )
  })

  it('rejects a data URI with a disallowed mime type', () => {
    const lambda = secureHref()
    expect(lambda('data:application/pdf;base64,QUJD', identityRender)).toBe('')
  })

  it('rejects a data URI with an allowed mime type but invalid base64 payload', () => {
    const lambda = secureHref()
    expect(lambda('data:image/png;base64,not-base64!!', identityRender)).toBe(
      '',
    )
  })
})
