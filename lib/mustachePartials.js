// Mustache partials shared between HTMLTemplate2_0.js and HTMLTemplate2_1.js.
// These are identical between CSAF 2.0 and 2.1, unlike PRODUCT_STATUS_HEADER
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

export const VULNERABILITY_NOTE = `
{{#title}}<b>{{.}}</b>{{/title}}{{#audience}} ({{.}}){{/audience}}
{{#text}}<p>{{{text}}}</p>{{/text}}`

export const DOCUMENT_NOTE = `
{{#title}}<h2>{{.}}</h2>{{/title}}
{{#audience}}<small>{{.}}</small>{{/audience}}
{{#text}}<p>{{{text}}}</p>{{/text}}`

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
