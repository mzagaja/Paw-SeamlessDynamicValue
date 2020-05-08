import URI from "urijs"

@registerDynamicValueClass
class SeamlessDynamicValue {
  static identifier = 'com.luckymarmot.PawExtensions.SeamlessDynamicValue';
  static title = 'Seamless Docs API Authentication';
  static inputs = [
    DynamicValueInput("secret", "Seamless Secret Key", "String")
  ];

  signHmac256(input, key) {
    const dv = DynamicValue("com.luckymarmot.HMACDynamicValue", {
      input: input,
      key: key,
      algorithm: 3 /* = SHA256 */,
      uppercase: false /* keep hashes lowercase */,
      encoding: 'Hexadecimal' /* encode hash data in hexadecimal */,
    })
    return dv.getEvaluatedString()
  }

  getStringToSign(request) {
    const uri = URI(request.url)

    /* Create the string to sign according to the following pseudo-grammar
     *
     * StringToSign = HTTPVerb + "+" +
     *                HTTPRequestURI + "+" +
     *                <timestamp>
     * See: http://developers.seamlessdocs.com/v1.2/docs/signing-requests#signature-base
     *
     * The HTTPRequestURI component is the HTTP absolute path component of the
     * URI up to, but not including, the query string. If the HTTPRequestURI is
     * empty, use a forward slash ( / ).
     */
    const timestamp = DynamicValue("com.luckymarmot.TimestampDynamicValue", {
                          format: 1
                      }).getEvaluatedString()
    const stringToSign = request.method + "+" +
                         uri.segment(0, "").pathname() + "+" +
                         timestamp
    return stringToSign
  }

  evaluate(context) {
    const request = context.getCurrentRequest()
    const stringToSign = this.getStringToSign(request)

    /* Calculate an RFC 2104-compliant HMAC with the string you just created,
     * your AWS secret access key as the key, and SHA256 as the hash algorithm.
     * Convert the resulting value to base64.
     */
    const signature = this.signHmac256(stringToSign, this.secret)

    /* Use the resulting value as the value of the Signature request parameter.
     * The final signature you send in the request must be URL encoded as
     * specified in RFC 3986. If your toolkit URL encodes your final request,
     * then it handles the required URL encoding of the signature. If your
     * toolkit doesn't URL encode the final request, then make sure to URL
     * encode the signature before you include it in the request.
     */
    return encodeURIComponent(signature)
  }
}
