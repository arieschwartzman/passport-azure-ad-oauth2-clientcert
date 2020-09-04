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

```javascript
    passport.use(new AzureAdOAuth2CertStrategy({
        authorizationURL: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        tokenURL:'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        clientID: '<client Id>',
        callbackURL: '<redirect url>',
        fingerprint: '<base64 fingerprint string>',
        pem: '<PEM file content>'
    },
        function (accessToken, refresh_token, params, profile, done) {
            var decodedToken = jwt.decode(params.id_token);
            const userProfile = {
                displayName: decodedToken.name,
                emails: [{ value: decodedToken.preferred_username.toLowerCase() }],
                roles: decodedToken.roles,
                tenantID: decodedToken.tid
            };
            done(undefined, userProfile);
    }));    

```
Setup route handler for the root of your application that needs to be protected for authorized users only.

```javascript
app.get('/', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/auth/azureadoauth2');
    }
    return res.render('index', { user: req.user });
});
```

Setup route that will be called when authentication is needed
```javascript
app.get('/auth/azureadoauth2',
    passport.authenticate('azure_ad_oauth2_clientcert', authOptions),
    function (req, res) {
        res.redirect('/');
    });

```
Setup route that will handle the authentication flow after user was authenticated. In this step, we exchange the authorization code with the access token by calling the token endpoint using the client certificate

```javascript
app.get('/auth/azureadoauth2/callback',
    passport.authenticate('azure_ad_oauth2_clientcert', { failureRedirect: '/login' }),
    function (req, res) {
        res.redirect('/');
    });

```
Setup route that will logout the user
```javascript
app.get('/logout', (req, res) => {
    req.logOut();
    return res.redirect('/');
});

```

## Obtain the fingerprint

Running this openssl command will get the fingerprint in Hex string format
```sh
openssl x509 -in cert.pem -fingerprint -noout

SHA1 Fingerprint=23:A8:18:44:F5:D5:0B:C4:D4:AC:76:9E:5B:1E:A7:57:B6:DA:91:45
```
This command will also remove the *SHA1 Fingerprint=* prefix and convert to base64 string
```sh
echo $(openssl x509 -in cert.pem -fingerprint -noout) | sed 's/SHA1 Fingerprint=//g' | sed 's/://g' | xxd -r -ps | base64

```