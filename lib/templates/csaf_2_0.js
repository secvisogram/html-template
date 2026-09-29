import { BIG, HEAD, MID, TAIL } from './sharedTemplateParts.js'

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

export default `${HEAD}
${CVSS}
${MID}
${CWE}
${BIG}
${TAIL}`
