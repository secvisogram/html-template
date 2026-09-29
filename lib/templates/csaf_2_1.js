import { BIG, HEAD, MID, TAIL } from './sharedTemplateParts.js'

const CVSS = `      <td>{{document.max_base_score_cvss_label}} Base Score: {{document.max_base_score}}</td>`

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
      {{/disclosure_date}}`

const SHARING_GROUP = `      {{#sharing_group}}
      <b>Sharing Group</b><br>
      <p>Id: {{id}}<p>
      <p>Name: {{name}}<p>
      {{/sharing_group}}
    </p>
    <p>`

export default `${HEAD}
${CVSS}
${MID}
${CWE}
${BIG}
${SHARING_GROUP}
${TAIL}`
