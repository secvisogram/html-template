import { buildTemplate } from './sharedTemplateParts.js'

const CVSS = `      <td>CVSSv3.1 Base Score: {{document.max_base_score}}</td>`

const CWE = `      <tr>
        <th>CWE:</th>
        <td>{{#cwe}}{{id}}:{{name}}{{/cwe}}</td>
      </tr>
      {{#id}}
        <tr>
          <th>ID:</th>
          <td>{{text}}{{#system_name}} ({{.}}){{/system_name}}</td>
        </tr>
      {{/id}}
      {{#discovery_date}}
        <tr>
          <th>Discovery date:</th>
          <td>{{discovery_date}}</td>
        </tr>
      {{/discovery_date}}
      {{#release_date}}
        <tr>
          <th>Release date:</th>
          <td>{{release_date}}</td>
        </tr>
      {{/release_date}}`

// CSAF 2.0 only: removed in CSAF 2.1 in favor of document.involvement.
const INVOLVEMENTS = `

    {{#involvements.length}}
      <h4>Involvement</h4>
      <ul>
      {{#involvements}}
        {{#.}}
      <li>{{#date}}{{.}} {{/date}}{{#upperCase}}{{party}}{{/upperCase}}{{#status}} ({{#replaceUnderscores}}{{.}}{{/replaceUnderscores}}){{/status}}{{#summary}}: {{{.}}}{{/summary}}</li>
        {{/.}}
      {{/involvements}}
      </ul>
    {{/involvements.length}}`

// CSAF 2.0: `contact_details` is a plain string.
const PUBLISHER_CONTACT = `    <p>{{contact_details}}</p>`

export default buildTemplate({
  cvss: CVSS,
  vulnerabilityRows: CWE,
  involvements: INVOLVEMENTS,
  publisherContact: PUBLISHER_CONTACT,
})
