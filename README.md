# Google-FPA-v2-Authorization-header
Google's internal source code for GFE for generating FPA v2 Authorization header
# Workflow of the Code
This new FPA system version 2 works with three user identifiers included in the hash:
```javascript
* @param {?Array<{key:string,value:string}>=} opt_userIdentifiers an
 * array of {key:, value:} objects where 'key' is: <li>
 * <ul>'e': denotes that the corresponding 'value' is the user's email address
 * <ul>'u': denotes that the corresponding 'value' is the user's
 *          focus-obfuscated Gaia ID
 * <ul>'a': denotes that the corresponding 'value' is the user account's
 *          app domain (required only for dasher accounts)
```
**The token can then be generated with:**
```javascript
// Extract identifier keys (e.g. "e", "u", "a") and values (email, gaia id, domain)
goog.array.forEach(userIdentifiers, function (element, index, array) {
  suffix.push(element["key"]);        // ["e", "u"] -> "eu"
  identifiers.push(element["value"]); // ["user@gmail.com", "ABC123"]
});

// Get current Unix timestamp
const timestamp = Math.floor(new Date().getTime() / 1000);

// Build SHA1 input: "email:gaiaId timestamp sessionCookie origin"
if (goog.array.isEmpty(identifiers)) {
  sha1Parts = [timestamp, sessionCookie, origin];
} else {
  sha1Parts = [identifiers.join(":"), timestamp, sessionCookie, origin];
}

// Compute SHA1 hash of space-joined parts
const sha1 = gapix.auth_firstparty.tokencrafter.computeSha1_(
  sha1Parts.join(" ")
);

// Final token: "timestamp_sha1hash_identifierKeys" e.g. "1739700391_abc123def_eu"
const tokenParts = [timestamp, sha1];
if (!goog.array.isEmpty(suffix)) {
  tokenParts.push(suffix.join(""));
}
return tokenParts.join("_");
```
>Gaia means _Google Accounts and ID Administration_. Every Google account has a sequential unobfuscated Gaia ID
>e.g 883333233322, as well as a longer identifier, the *Focus-obfuscated Gaia ID*, which looks like 11234567891234567898.

This means the final token format is `<timestamp>_<hash>_<identifier_key>`. E.g, *Google Workspace user*(internally called dasher)'s token might look like 1738383839_abc123def456_eua where *eua* indicates the hash was computed using email, obfuscated Gaia ID, and Google Workspace domain. The origin used in the hash is the *Origin* header value (eg. <ins>https://drive.google.com<ins>)

>Note: There are only three possible user identifier keys: *U* for obfuscated Gaia ID, *e* for email, and *a* for Google >Workspace domain. If you specify other letters, the API backend just ignores them. So it's actually possible to mint a >valid auth header containing arbitrary strings like `<timestamp>_<hash>_googlesauthteamdoeswhatevertheywant`
