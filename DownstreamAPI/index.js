const express = require('express');
const morgan = require('morgan');
const passport = require('passport');
require('dotenv').config();
const config = require('./config');
const BearerStrategy = require('passport-azure-ad').BearerStrategy;

config.credentials.tenantID = process.env.API_TENANT_ID;
config.credentials.clientID = process.env.API_APP_ID;

const options = {
  identityMetadata: `https://${config.metadata.authority}/${config.credentials.tenantID}/${config.metadata.version}/${config.metadata.discovery}`,
  issuer: `https://${config.metadata.authority}/${config.credentials.tenantID}/${config.metadata.version}`,
  clientID: config.credentials.clientID,
  audience: config.credentials.clientID,
  validateIssuer: config.settings.validateIssuer,
  passReqToCallback: config.settings.passReqToCallback,
  loggingLevel: config.settings.loggingLevel,
};
const bearerStrategy = new BearerStrategy(options, (token, done) => {
  // Send user info using the second argument
  done(null, {}, token);
});
const app = express();

app.use(morgan('dev'));
app.use(passport.initialize());
passport.use(bearerStrategy);

// Enable CORS (in production, modify as to allow only designated origins)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Authorization, Origin, X-Requested-With, Content-Type, Accept');
  next();
});

// API endpoint exposed
app.get('/api', passport.authenticate('oauth-bearer', { session: false }), (req, res) => {
  console.log('Validated claims: ', req.authInfo);

  // The access token the user sent
  const accessToken = req.get('authorization');

  // View JWT issued by AAD: https://jwt.ms
  console.log('accessToken:', accessToken);

  // service relies on the name claim.
  res.status(200).json({
    name: req.authInfo['name'],
    email: req.authInfo.preferred_username,
    'issued-by': req.authInfo['iss'],
    'issued-for': req.authInfo['aud'],
    scope: req.authInfo['scp'],

    // Records the identity provider that authenticated the subject of the token.
    // This value is identical to the value of the Issuer claim unless the user account not in the same tenant as the issuer - guests, for instance.
    // If the claim is not present, it means that the value of iss can be used instead.
    // For personal accounts being used in an orgnizational context (for instance, a personal account invited to an Azure AD tenant), the idp claim may be 'live.com' or an STS URI containing the Microsoft account tenant id.
    'identity-provider': req.authInfo.idp,
  });
});

const port = process.env.PORT || 7000;

app.listen(port, () => {
  console.log('Listening on port ' + port);
});

module.exports = app;
