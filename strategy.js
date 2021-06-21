
var util = require('util')
,OAuth2Strategy = require('passport-azure-ad-oauth2')
,jwt = require('jsonwebtoken')
,crypto = require("crypto")

function Strategy (options, verify) {
  options = options || {};
  OAuth2Strategy.call(this, options, verify);
  this.name = 'azure_ad_oauth2_clientcert';
  this.clientAssertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
  this.pem = options.pem;
}

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.tokenParams = function (options) {

  var params = params || {};
  params['client_assertion_type'] = this.clientAssertionType;

  const baseString = this.pem.match(/-----BEGIN CERTIFICATE-----\s*([\s\S]+?)\s*-----END CERTIFICATE-----/i);
  const rawCert = Buffer.from(baseString[1], "base64");
  const fingerprint = crypto.createHash("sha1").update(rawCert).digest("base64");
  const fingerprintHex = crypto.createHash("sha1").update(rawCert).digest("hex");
  console.log(`${(new Date()).toISOString()}: passport-azure-ad-ouath2-clientcert::Using certificate thumbprint ${fingerprintHex}`);

  var additionalHeaders = {
      'x5t': fingerprint,
      'x5c': baseString[1]
  };

  const certJwt = {
      'aud': this._oauth2._accessTokenUrl,
      'iss': this._oauth2._clientId,
      'sub': this._oauth2._clientId,
      'jti': '' + Math.random(),
      'nbf': Math.floor(Date.now() / 1000) - 1000,
      'exp': Math.floor(Date.now() / 1000) + 7 * 8640000
  };

  // Sign the JWT with the PEM key
  const jwtToken = jwt.sign(certJwt, this.pem, { algorithm: 'RS256', header: additionalHeaders });
  params['client_assertion'] = jwtToken;
  return params;
}

module.exports = Strategy;