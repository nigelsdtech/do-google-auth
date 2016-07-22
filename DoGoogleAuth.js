"use strict"

var fs         = require('fs');
var readline   = require('readline');
var googleAuth = require('google-auth-library');

var scopes
  , tokenFile
  , tokenDir
  , clientSecretFile

function doGoogleAuth(scopes,tokenFile,tokenDir,clientSecretFile) {

  this.scopes           = (Array.isArray(scopes))? scopes.join(" ") : scopes
  this.tokenFile        = tokenFile
  this.tokenDir         = tokenDir
  this.clientSecretFile = clientSecretFile
}

var method = doGoogleAuth.prototype

/**
 * Create an OAuth2 client with the given credentials, and then execute the
 * given callback function.
 *
 * @param {function} callback The callback to call with the authorized client.
 */
method.authorize = function (callback) {

  var self = this

  // Load client secrets from a local file.
  var content = ""

  try {
    var content = fs.readFileSync(this.clientSecretFile, 'utf8')
  } catch (err) {
    console.log('Error loading client secret file: ' + err);
    callback(err)
    return null;
  }

  var credentials  = JSON.parse(content)

  var clientSecret = credentials.installed.client_secret;
  var clientId     = credentials.installed.client_id;
  var redirectUrl  = credentials.installed.redirect_uris[0];
  var auth         = new googleAuth();
  var oauth2Client = new auth.OAuth2(clientId, clientSecret, redirectUrl);

  var tokenPath = this.tokenDir + '/' + this.tokenFile;

  // Check if we have previously stored a token.
  fs.readFile(tokenPath, function(err, token) {
    if (err) {
      self.getNewToken(oauth2Client, callback);
    } else {
      oauth2Client.credentials = JSON.parse(token);
      callback(null,oauth2Client);
    }
  });
}

/**
 * Get and store new token after prompting for user authorization, and then
 * execute the given callback with the authorized OAuth2 client.
 *
 * @param {google.auth.OAuth2} oauth2Client The OAuth2 client to get token for.
 * @param {getEventsCallback} callback The callback to call with the authorized
 *     client.
 */
method.getNewToken = function (oauth2Client, callback) {

  var self = this

  var authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: this.scopes
  });
  console.log('Authorize this app by visiting this url: ', authUrl);
  var rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  rl.question('Enter the code from that page here: ', function(code) {
    rl.close();
    oauth2Client.getToken(code, function(err, token) {
      if (err) {
        console.log('Error while trying to retrieve access token', err);
        callback(err)
        return null;
      }
      oauth2Client.credentials = token;
      self.storeToken(token);
      callback(null,oauth2Client);
    });
  });
}

/**
 * Store token to disk be used in later program executions.
 *
 * @param {Object} token The token to store to disk.
 */
method.storeToken = function (token) {
  try {
    fs.mkdirSync(this.tokenDir);
  } catch (err) {
    if (err.code != 'EEXIST') {
      throw err;
    }
  }
  var tokenPath = this.tokenDir + '/' + this.tokenFile;
  fs.writeFile(tokenPath , JSON.stringify(token));
  console.log('Token stored to ' + tokenPath);
}


module.exports = doGoogleAuth;
