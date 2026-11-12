// Mustache partials shared between HTMLTemplate2_0.js and HTMLTemplate2_1.js.
// These are identical between CSAF 2.0 and 2.1 (the 2.1-only properties they
// render, like note product_ids, are simply absent in 2.0 documents), unlike
// PRODUCT_STATUS_HEADER
// and PRODUCT_STATUS_ROW (which differ - CSAF 2.1 adds a CVSS Version
// column), so those two stay defined separately in each HTMLTemplate file.

export const REMEDIATION = `
<h5>{{#replaceUnderscores}}{{#upperCase}}{{category}}{{/upperCase}}{{/replaceUnderscores}}{{#date}} ({{.}}){{/date}}</h5>
<p>{{{details}}}</p>
{{#product_ids.length}}
  <h6>For products:</h6>
  <ul>
  {{#product_ids}}
    <li>{{name}}</li>
  {{/product_ids}}
  </ul>
{{/product_ids.length}}
{{#group_ids.length}}
  <h6>For groups:</h6>
  <ul>
  {{#group_ids}}
   <li>{{{name}}}</li>
  {{/group_ids}}
  </ul>
{{/group_ids.length}}
<p>{{#url}}{{> url }}{{/url}}</p>
{{#entitlements}}
  <p>{{{.}}}</p>
{{/entitlements}}
{{#restart_required}}
  Restart required: <b>{{category}}</b>
  <p>{{{details}}}</p>
{{/restart_required}}`

export const THREAT = `
<h5>{{#replaceUnderscores}}{{#upperCase}}{{category}}{{/upperCase}}{{/replaceUnderscores}}{{#date}} ({{.}}){{/date}}</h5>
<p>{{{details}}}</p>
{{#product_ids.length}}
  <h6>For products:</h6>
  <ul>
  {{#product_ids}}
    <li>{{name}}</li>
  {{/product_ids}}
  </ul>
{{/product_ids.length}}
{{#group_ids.length}}
  <h6>For groups:</h6>
  <ul>
  {{#group_ids}}
   <li>{{{name}}}</li>
  {{/group_ids}}
  </ul>
{{/group_ids.length}}`

// Lists the products/groups an item is scoped to. Only CSAF 2.1 has items
// carrying `product_ids`/`group_ids` besides remediations and threats (notes,
// vulnerability ids, first known exploitation dates, involvement actions); for
// all other items, and for all CSAF 2.0 documents, this renders nothing.
export const SCOPE = `
{{#product_ids.length}}
  <h6>For products:</h6>
  <ul>
  {{#product_ids}}
    <li>{{name}}</li>
  {{/product_ids}}
  </ul>
{{/product_ids.length}}
{{#group_ids.length}}
  <h6>For groups:</h6>
  <ul>
  {{#group_ids}}
   <li>{{{name}}}</li>
  {{/group_ids}}
  </ul>
{{/group_ids.length}}`

// CSAF 2.1 `contact_t` (publisher.contact, involvement.entities[].contact).
export const CONTACT = `
{{#details}}<p>{{{.}}}</p>{{/details}}
{{#email}}<p>Email: <a {{#secureHref}}mailto:{{.}}{{/secureHref}}>{{.}}</a></p>{{/email}}
{{#url}}<p>URL: {{> url}}</p>{{/url}}
{{#public_openpgp_key_url}}<p>Public OpenPGP key: {{> url}}</p>{{/public_openpgp_key_url}}`

export const VULNERABILITY_NOTE = `
{{#title}}<b>{{.}}</b>{{/title}}{{#audience}} ({{.}}){{/audience}}
{{#text}}<p>{{{text}}}</p>{{/text}}
{{> scope}}`

export const DOCUMENT_NOTE = `
{{#title}}<h2>{{.}}</h2>{{/title}}
{{#audience}}<small>{{.}}</small>{{/audience}}
{{#text}}<p>{{{text}}}</p>{{/text}}
{{> scope}}`

export const ACKNOWLEDGEMENT = `
{{#.}}
  <li>{{#removeTrailingComma}}{{#names}}{{.}}, {{/names}}{{/removeTrailingComma}}{{#organization}}{{#names.length}} from {{/names.length}}{{.}} {{/organization}}{{#summary}} for {{{.}}}{{/summary}}{{#urls.length}} (see: {{#removeTrailingComma}}{{#urls}}{{> url}}, {{/urls}}{{/removeTrailingComma}}){{/urls.length}}</li>
{{/.}}`

export const REFERENCE = `
{{#.}}
  <li>{{{summary}}} {{#category}} ({{#replaceUnderscores}}{{.}}{{/replaceUnderscores}}){{/category}}{{#url}}{{> url}}{{/url}}</li>
{{/.}}`

export const URL = `
{{#.}}
  <a {{#secureHref}}{{.}}{{/secureHref}}>{{.}}</a>
{{/.}}
`
