import Mustache from 'mustache'
import Template from './templates/csaf_2_0.js'
import {
  ACKNOWLEDGEMENT,
  DOCUMENT_NOTE,
  REFERENCE,
  REMEDIATION,
  THREAT,
  URL,
  VULNERABILITY_NOTE,
} from './mustachePartials.js'

const PRODUCT_STATUS_HEADER = `
<thead>
  <tr>
    <th>Product</th>
    <th>CVSS-Vector</th>
    <th>CVSS Base Score</th>
  </tr>
</thead>`

const PRODUCT_STATUS_ROW = `
<tr>
  <td>{{name}}</td>
  <td>{{vectorString}}</td>
  <td>{{baseScore}}</td>
</tr>`

/**
 * Encapsulates the rendering of the mustache template.
 *
 * @param {{ document: {} }} props
 */
export default function HTMLTemplate2_0({ document }) {
  return Mustache.render(Template, document, {
    product_status_header: PRODUCT_STATUS_HEADER,
    product_status_row: PRODUCT_STATUS_ROW,
    remediation: REMEDIATION,
    threat: THREAT,
    vulnerability_note: VULNERABILITY_NOTE,
    document_note: DOCUMENT_NOTE,
    acknowledgment: ACKNOWLEDGEMENT,
    reference: REFERENCE,
    url: URL,
  })
}
