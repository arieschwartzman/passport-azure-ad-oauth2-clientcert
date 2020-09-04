# Passport-azure-ad-oauth2-clientcert

[Passport](http://passportjs.org/) strategy for authenticating with [Azure AD](http://msdn.microsoft.com/en-us/library/azure/dn645545.aspx)
using the OAuth 2.0 protocol and X.509 client certificate



## Install

    $ npm install passport-azure-ad-oauth2-clientcert

## Overview

When using authorization code flow or hybrid flow in OpenID Connect, the client exchanges an authorization code for an access token. During this step, the client has to authenticate itself to the server.

One way to authenticate the client is by using a client secret like done with this [passport strategy](https://www.npmjs.com/package/passport-azure-ad-oauth2), which my package is extending.

The secret is just a string, so you have to make sure not to leak the value. The best practice is to keep the client secret out of source control. When you deploy to Azure, store the secret in an app setting.

However, anyone with access to the Azure subscription can view the app settings. Furthermore, there is always a temptation to check secrets into source control (for example, in deployment scripts), share them by email, and so on.

For additional security, you can use [client assertion](https://tools.ietf.org/html/rfc7521) instead of a client secret. With client assertion, the client uses an X.509 certificate to prove the token request came from the client. The client certificate is installed on the web server. Generally, it will be easier to restrict access to the certificate, than to ensure that nobody inadvertently reveals a client secret. For more information about configuring certificates in a web app, see Using Certificates in [Azure Websites Applications](https://azure.microsoft.com/blog/using-certificates-in-azure-websites-applications)


## Usage
### Configure the strategy
Notice that the client_secret parameter is not used here. Instead, we pass two parameters:
1. **pem**: Content of a PEM file that contains the private key and the certificate. The private key is never sent on the wire, instead it's used to sign a JWT that will be eventually send to the Identity provider (AAD) to retrieve the access token.
2. **fingerprint**: SHA1 base64 representation of the certificate. It's placed in the additional header of the JWT that is signed with the private key



