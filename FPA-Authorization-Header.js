goog.provide("gapix.auth_firstparty.tokencrafter");

goog.require("gapix.crypto.sha1");
goog.require("gapix.util.getOrigin");
goog.require("goog.array");

/**
 * If the user is logged in, this will return a value for
 * the Authorization header used in First-Party authentication and OAuth 2
 * session_state.
 *
 * @param {string} location window.location.href of the first party request.
 * @param {string} apiSessionCookieValue the value of the API session cookie.
 * @param {string} authScheme auth scheme to use while crafting the  token.
 * @param {?Array<{key:string,value:string}>=} opt_userIdentifiers an
 * array of {key:, value:} objects where 'key' is: <li>
 * <ul>'e': denotes that the corresponding 'value' is the user's email address
 * <ul>'u': denotes that the corresponding 'value' is the user's
 *          focus-obfuscated Gaia ID
 * <ul>'a': denotes that the corresponding 'value' is the user account's
 *          app domain (required only for dasher accounts)
 * </li> Providing this optional argument will make the function compute a
 * time-varying First-Party authentication v2 Authorization header instead of
 * v1.
 * @param {?Array<string>=} opt_extraFields Additional hash input fields.
 *
 * @return {?string} the computed header value or null.
 */
gapix.auth_firstparty.tokencrafter.createAuthHeaderValueForFirstParty =
  function (
    location,
    apiSessionCookieValue,
    authScheme,
    opt_userIdentifiers,
    opt_extraFields
  ) {
    if (!!location && !!apiSessionCookieValue && !!authScheme) {
      return [
        authScheme,
        gapix.auth_firstparty.tokencrafter.getFirstPartyAuthToken_(
          gapix.util.getOrigin(location),
          apiSessionCookieValue,
          opt_userIdentifiers || null,
          opt_extraFields || []
        ),
      ].join(" ");
    }
    return null;
  };

/**
 * @param {string} origin The origin.
 * @param {string} sessionCookie The session cookie.
 * @param {?Array<{key:string,value:string}>} userIdentifiers The user
 *    identifiers; an Array here will trigger v2 time-varying token format.
 * @param {!Array<string>} extraFields Additional hash input fields.
 * @return {string} the auth token.
 * @private
 */
gapix.auth_firstparty.tokencrafter.getFirstPartyAuthToken_ = function (
  origin,
  sessionCookie,
  userIdentifiers,
  extraFields
) {
  const version = Array.isArray(userIdentifiers) ? 2 : 1;
  /** @type {!Array<string>} */
  let sha1Parts = [];

  if (version == 1) {
    sha1Parts = [sessionCookie, origin];
    goog.array.forEach(extraFields, function (element, index, array) {
      sha1Parts.push(element);
    });
    return gapix.auth_firstparty.tokencrafter.computeSha1_(sha1Parts.join(" "));
  } else {
    const identifiers = [];
    const suffix = [];
    goog.array.forEach(userIdentifiers, function (element, index, array) {
      suffix.push(element["key"]);
      identifiers.push(element["value"]);
    });

    const timestamp = Math.floor(new Date().getTime() / 1000);
    if (goog.array.isEmpty(identifiers)) {
      sha1Parts = [timestamp, sessionCookie, origin];
    } else {
      sha1Parts = [identifiers.join(":"), timestamp, sessionCookie, origin];
    }
    goog.array.forEach(extraFields, function (element, index, array) {
      sha1Parts.push(element);
    });
    const sha1 = gapix.auth_firstparty.tokencrafter.computeSha1_(
      sha1Parts.join(" ")
    );

    const tokenParts = [timestamp, sha1];
    if (!goog.array.isEmpty(suffix)) {
      tokenParts.push(suffix.join(""));
    }
    return tokenParts.join("_");
  }
};

/**
 * Compute four-hex-digits digest used to validate versionInfos in the LSOLH
 * cookie used in OAuth 2 approval-state invalidations. See go/lsolh for
 * details and background.
 * @param {?string=} opt_versionInfos The versionInfos from the LSOLH cookie.
 * @param {?string=} opt_sessionCookie The value of SAPISID, if present.
 * @return {?string} four-hex-digit digest (truncated SHA-1) used to validate
 *     session_state or null if opt_versionInfos is empty or missing.
 */
gapix.auth_firstparty.tokencrafter.computeVersionInfoDigest = function (
  opt_versionInfos,
  opt_sessionCookie
) {
  if (!opt_versionInfos) return null;
  const versionInfoDigestParts = [opt_versionInfos];
  if (!!opt_sessionCookie) versionInfoDigestParts.push(opt_sessionCookie);
  const versionInfoDigest = gapix.auth_firstparty.tokencrafter.computeSha1_(
    versionInfoDigestParts.join(" ")
  );
  return versionInfoDigest.substr(0, 4);
};

/**
 * Helper function to compute lowercase SHA1 hash of a given string.
 * TODO(bsittler,vvidya) to switch to goog.crypt.Sha1 once Chrome M36 is no
 * longer live or once goog.crypt.Sha1 grows a workaround for the V8 bug.
 * @param {string} toHash value to hash.
 * @return {string} lowercase hexadecimal SHA1 hash digest of toHash.
 * @private
 */
gapix.auth_firstparty.tokencrafter.computeSha1_ = function (toHash) {
  const sha1 = gapix.crypto.sha1();
  sha1.update(toHash);
  return sha1.digestString().toLowerCase();
};
