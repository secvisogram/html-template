import { buildTemplate } from './sharedTemplateParts.js'

const CVSS = `      <td>{{document.max_base_score_cvss_label}} Base Score: {{document.max_base_score}}</td>`

const LICENSE_EXPRESSION = `
    {{#document.license_expression}}
    <tr>
      <td colspan="2">License expression: {{.}}</td>
    </tr>
    {{/document.license_expression}}`

const CWE = `      <h4>CWE's</h4>
      {{#cwes}}
      <tr>
        <td>{{id}}:{{name}}:{{version}}</td>
      </tr>
      {{/cwes}}
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
      {{#disclosure_date}}
        <tr>
          <th>Disclosure date:</th>
          <td>{{disclosure_date}}</td>
        </tr>
      {{/disclosure_date}}
      {{#dl_vuln_id}}
        <tr>
          <th>Document-local ID:</th>
          <td>{{.}}</td>
        </tr>
      {{/dl_vuln_id}}`

const PRODUCT_STATUS_UNKNOWN = `

    {{#product_status.unknown.length}}
    <h5>Unknown</h5>
    <ul>
      {{#product_status.unknown}}
        <li>{{name}}</li>
      {{/product_status.unknown}}
    </ul>
    {{/product_status.unknown.length}}`

const VULNERABILITY_EXTRA = `

    {{#first_known_exploitation_dates.length}}
      <h4>First known exploitation dates</h4>
      {{#first_known_exploitation_dates}}
        <h5>{{exploitation_date}}{{#date}} (information from {{.}}){{/date}}</h5>
        {{> scope}}
      {{/first_known_exploitation_dates}}
    {{/first_known_exploitation_dates.length}}

    {{#ids_scoped.length}}
      <h4>Scoped IDs</h4>
      {{#ids_scoped}}
        <h5>{{text}}{{#system_name}} ({{.}}){{/system_name}}</h5>
        {{> scope}}
      {{/ids_scoped}}
    {{/ids_scoped.length}}

    {{#metrics_details.length}}
      <h4>Metrics</h4>
      {{#metrics_details}}
        <ul>
          {{#qualitative_severity_rating}}
            <li>Qualitative severity rating: {{#upperCase}}{{.}}{{/upperCase}}</li>
          {{/qualitative_severity_rating}}
          {{#epss}}
            <li>EPSS: probability {{probability}}, percentile {{percentile}} ({{timestamp}})</li>
          {{/epss}}
          {{#ssvc}}
            <li>SSVC{{#timestamp}} ({{.}}){{/timestamp}}
              <ul>
              {{#selections}}
                <li>{{label}}: {{values}}</li>
              {{/selections}}
              </ul>
            </li>
          {{/ssvc}}
          {{#products.length}}
            <li>For products: {{#removeTrailingComma}}{{#products}}{{name}}, {{/products}}{{/removeTrailingComma}}</li>
          {{/products.length}}
          {{#source}}
            <li>Source: {{> url}}</li>
          {{/source}}
        </ul>
      {{/metrics_details}}
    {{/metrics_details.length}}`

const PUBLISHER_CONTACT = `    {{#contact}}{{> contact}}{{/contact}}`

const INVOLVEMENT = `

  {{#document.involvement}}
    <h2>Involvement</h2>

    {{#entities.length}}
      <h3>Entities</h3>
      <ul>
      {{#entities}}
        <li>
          <b>{{display_name}}</b> ({{#replaceUnderscores}}{{category}}{{/replaceUnderscores}}, {{entity_id}})
          {{#contact}}{{> contact}}{{/contact}}
        </li>
      {{/entities}}
      </ul>
    {{/entities.length}}

    {{#entity_groups.length}}
      <h3>Entity groups</h3>
      <ul>
      {{#entity_groups}}
        <li>
          <b>{{name}}</b> ({{entity_group_id}})
          {{#summary}}<p>{{{.}}}</p>{{/summary}}
          {{#entity_ids.length}}
            <p>Members: {{#removeTrailingComma}}{{#entity_ids}}{{name}}, {{/entity_ids}}{{/removeTrailingComma}}</p>
          {{/entity_ids.length}}
        </li>
      {{/entity_groups}}
      </ul>
    {{/entity_groups.length}}

    {{#actions.length}}
      <h3>Actions</h3>
      <ul>
      {{#actions}}
        <li>
          <b>{{date}}</b>: {{#replaceUnderscores}}{{#upperCase}}{{category}}{{/upperCase}}{{/replaceUnderscores}} ({{#replaceUnderscores}}{{status}}{{/replaceUnderscores}}, {{action_id}})
          {{#acting_entity_refs.length}}
            <br>By: {{#removeTrailingComma}}{{#acting_entity_refs}}{{name}}, {{/acting_entity_refs}}{{/removeTrailingComma}}
          {{/acting_entity_refs.length}}
          {{#receiving_entity_refs.length}}
            <br>To: {{#removeTrailingComma}}{{#receiving_entity_refs}}{{name}}, {{/receiving_entity_refs}}{{/removeTrailingComma}}
          {{/receiving_entity_refs.length}}
          {{#dl_vuln_ids.length}}
            <br>Vulnerabilities: {{#removeTrailingComma}}{{#dl_vuln_ids}}{{.}}, {{/dl_vuln_ids}}{{/removeTrailingComma}}
          {{/dl_vuln_ids.length}}
          {{#referenced_action_ids.length}}
            <br>Refers to actions: {{#removeTrailingComma}}{{#referenced_action_ids}}{{.}}, {{/referenced_action_ids}}{{/removeTrailingComma}}
          {{/referenced_action_ids.length}}
          {{#summary}}<p>{{{.}}}</p>{{/summary}}
          {{> scope}}
        </li>
      {{/actions}}
      </ul>
    {{/actions.length}}
  {{/document.involvement}}`

const SHARING_GROUP = `      {{#sharing_group}}
      <b>Sharing Group</b><br>
      <p>Id: {{id}}<p>
      <p>Name: {{name}}<p>
      {{/sharing_group}}
    </p>
    <p>`

export default buildTemplate({
  cvss: CVSS,
  headerRows: LICENSE_EXPRESSION,
  vulnerabilityRows: CWE,
  productStatusExtra: PRODUCT_STATUS_UNKNOWN,
  vulnerabilityExtra: VULNERABILITY_EXTRA,
  publisherContact: PUBLISHER_CONTACT,
  documentExtra: INVOLVEMENT,
  sharingGroup: SHARING_GROUP,
})
