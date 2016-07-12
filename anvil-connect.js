/* global localStorage, b64utohex, sjcl, KJUR, CryptoJS, jQuery, $, location */
const sjcl = require('sjcl')
const jsrsasign = require('jsrsasign')
const base64url = require('base64url')
const CryptoJS = require('crypto-js')
'use strict'

const Anvil = {}

var issuer, jwk, params, display
var session = {}

/**
 * Extend
 */

const extend = function () {
  var target = arguments[0]

  // iterate over arguments, excluding the first arg
  for (var i = 1; i < arguments.length; i++) {
    var source = arguments[i]

    // iterate through properties, copying to target
    for (var prop in source) {
      if (source[prop] !== undefined) { target[prop] = source[prop] }
    }
  }

  return target
}

/**
 * Set JWK
 */

const setJWK = function (jwks) {
  var key = 'anvil.connect.jwk'

  // Recover from localStorage.
  if (!jwks) {
    try {
      jwk = JSON.parse(localStorage[key])
    } catch (e) {
      console.log('Cannot deserialized JWK')
    }
  }

  // Argument is a naked object.
  if (!Array.isArray(jwks) && typeof jwks === 'object') {
    jwk = jwks
  }

  // Argument is an array of JWK objects.
  // Find the key for verifying signatures.
  if (Array.isArray(jwks)) {
    jwks.forEach(function (obj) {
      if (obj && obj.use === 'sig') {
        jwk = obj
      }
    })
  }

  if (jwk) {
    localStorage[key] = JSON.stringify(jwk)
  }
}

Anvil.setJWK = setJWK

/**
 * Provider configuration
 */

function configure (options) {
  this.issuer = issuer = options.issuer

  setJWK(options.jwk)

  this.params = params = {}
  this.params.response_type = options.response_type || 'id_token token'
  this.params.client_id = options.client_id
  this.params.redirect_uri = options.redirect_uri
  this.params.scope = [
    'openid',
    'profile'
  ].concat(options.scope).join(' ')
  this.display = display = options.display || 'page'
}

Anvil.configure = configure

/**
 * Form Urlencode an object
 */

const toFormUrlEncoded = function (obj) {
  var pairs = []

  Object.keys(obj).forEach(function (key) {
    pairs.push(encodeURIComponent(key) + '=' + encodeURIComponent(obj[key]))
  })

  return pairs.join('&')
}

Anvil.toFormUrlEncoded = toFormUrlEncoded

/**
 * Parse Form Urlencoded data
 */

const parseFormUrlEncoded = function (str) {
  var obj = {}

  str.split('&').forEach(function (property) {
    var pair = property.split('=')
    var key = decodeURIComponent(pair[0])
    var val = decodeURIComponent(pair[1])

    obj[key] = val
  })

  return obj
}

Anvil.parseFormUrlEncoded = parseFormUrlEncoded

/**
 * Get URI Fragment
 */

function getUrlFragment (url) {
  return url.split('#').pop()
}

Anvil.getUrlFragment = getUrlFragment

/**
 * Configure the authorize popup window
 * Adapted from dropbox-js for ngDropbox
 */

function popup (popupWidth, popupHeight) {
  var x0, y0, width, height, popupLeft, popupTop

  // Metrics for the current browser window.
  x0 = window.screenX || window.screenLeft
  y0 = window.screenY || window.screenTop
  width = window.outerWidth || document.documentElement.clientWidth
  height = window.outerHeight || document.documentElement.clientHeight

  // Computed popup window metrics.
  popupLeft = Math.round(x0) + (width - popupWidth) / 2
  popupTop = Math.round(y0) + (height - popupHeight) / 2.5
  if (popupLeft < x0) { popupLeft = x0 }
  if (popupTop < y0) { popupTop = y0 }

  return 'width=' + popupWidth + ',height=' + popupHeight + ',' +
  'left=' + popupLeft + ',top=' + popupTop + ',' +
  'dialog=yes,dependent=yes,scrollbars=yes,location=yes'
}

Anvil.popup = popup

/**
 * Session object
 */

Anvil.session = session

/**
 * Serialize session
 */

function serialize () {
  var now = new Date()
  var time = now.getTime()
  var exp = time + (Anvil.session.expires_in || 3600) * 1000
  var random = Math.random().toString(36).substr(2, 10)
  var secret = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(random))

  now.setTime(exp)
  document.cookie = 'anvil.connect=' + secret +
    '; expires=' + now.toUTCString()

  var encrypted = sjcl.encrypt(secret, JSON.stringify(Anvil.session))
  localStorage['anvil.connect'] = encrypted
  localStorage['anvil.connect.session.state'] = Anvil.sessionState
// console.log('SERIALIZED', encrypted)
}

Anvil.serialize = serialize

/**
 * Deserialize session
 */

function deserialize () {
  var re, secret, json, parsed

  try {
    // Use the cookie value to decrypt the session in localStorage
    re = /\banvil\.connect=([^\s;]*)/
    secret = document.cookie.match(re).pop()
    json = sjcl.decrypt(secret, localStorage['anvil.connect'])
    parsed = JSON.parse(json)
  } catch (e) {
    // console.log('Cannot deserialize session data')
  }

  Anvil.session = session = parsed || {}
  Anvil.sessionState = localStorage['anvil.connect.session.state']
  return Anvil.session
}

Anvil.deserialize = deserialize

/**
 * Reset
 */

function reset () {
  Anvil.session = session = {}
  document.cookie = 'anvil.connect=; expires=Thu, 01 Jan 1970 00:00:01 GMT;'
  delete localStorage['anvil.connect']
}

Anvil.reset = reset

/**
 * Quick and dirty uri method with nonce
 */

function uri (endpoint, options) {
  return issuer + '/' +
  (endpoint || 'authorize') + '?' +
  toFormUrlEncoded(extend({}, params, options, {
    nonce: this.nonce()
  }))
}

Anvil.uri = uri

/**
 * Create or verify a nonce
 */

const nonce = function (nonce) {
  if (nonce) {
    return (sha256url(localStorage['nonce']) === nonce)
  } else {
    localStorage['nonce'] = Math.random().toString(36).substr(2, 10)
    return sha256url(localStorage['nonce'])
  }
}

Anvil.nonce = nonce

/**
 * Base64url encode a SHA256 hash of the input string
 */

const sha256url = function (str) {
  return sjcl.codec.base64url.fromBits(sjcl.hash.sha256.hash(str))
}

Anvil.sha256url = sha256url

/**
 * Headers
 */

function headers (headers) {
  if (this.session.access_token) {
    return extend(headers || {}, {
      'Authorization': 'Bearer ' + this.session.access_token
    })
  } else {
    return headers
  }
}

Anvil.headers = headers

/**
 * Request
 */

function request (config) {
  config.headers = this.headers(config.headers)
  config.crossDomain = true
  return fetch(config.url, config).then(function(r) { return r.json()})
}

Anvil.request = request

/**
 * UserInfo
 */

function userInfo () {
  return this.request({
    method: 'GET',
    url: issuer + '/userinfo',
    crossDomain: true
  })
}

Anvil.userInfo = userInfo

/**
 * Callback
 */

function callback (response) {
  return new Promise(function(resolve, reject) {
    if (response.error) {
      // clear localStorage/cookie/etc
      Anvil.sessionState = response.session_state
      localStorage['anvil.connect.session.state'] = Anvil.sessionState
      Anvil.reset()
      reject(response)
    } else {
      // NEED TO REVIEW THIS CODE FOR SANITY
      // Check the conditions in which some of these verifications
      // are skipped.

      function verify (token) {
        const hN = base64url.decode(jwk.n, 'hex')
        const hE = base64url.decode(jwk.e, 'hex')
        const pubkey = jsrsasign.KEYUTIL.getKey({ n: hN, e: hE })

        return jsrsasign.jws.JWS.verify(token, pubkey)
      }

      function parseClaims (token) {
        const claims = token.split('.')[1]

        return JSON.parse(base64url.decode(claims))
      }
      // Decode the access token and verify signature
      if (response.access_token &&
        !verify(response.access_token)) {
        reject('Failed to verify access token signature.')
      }

      // Decode the id token and verify signature
      if (response.id_token &&
        !verify(response.access_token)) {
        reject('Failed to verify id token signature.')
      }

      // Parse the access token payload
      try {
        response.access_claims = parseClaims(response.access_token)
      } catch (e) {
        reject("Can't parse access token payload.")
      }

      // Parse the id token payload
      try {
        response.id_claims = parseClaims(response.id_token)
      } catch (e) {
        reject("Can't parse id token payload.")
      }

      // Validate the nonce
      if (response.id_claims && !nonce(response.id_claims.nonce)) {
        reject('Invalid nonce.')
      }

      // Verify at_hash
      if (['id_token token'].indexOf(params.response_type) !== -1) {
        var atHash = CryptoJS
          .SHA256(response.access_token)
          .toString(CryptoJS.enc.Hex)
        atHash = atHash.slice(0, atHash.length / 2)
        if (response.id_claims && atHash !== response.id_claims.at_hash) {
          reject('Invalid access token hash in id token payload')
        }
      }

      Anvil.session = session = response
      Anvil.sessionState = response.session_state
      // console.log('CALLBACK SESSION STATE', Anvil.sessionState)

      Anvil.userInfo().then(
        function userInfoSuccess (userInfo) {
          Anvil.session.userInfo = userInfo
          Anvil.serialize()
          resolve(session)
        },

        function userInfoFailure () {
          reject('Retrieving user info from server failed.')
        }
      )
    }
  })
}

Anvil.callback = callback

/**
 * Authorize
 */

function authorize () {
  // handle the auth response
  if (location.hash) {
    return Anvil.callback(parseFormUrlEncoded(location.hash.substring(1)))

  // initiate the auth flow
  } else {
    Anvil.destination(location.pathname)

    // open the signin page in a popup window
    if (display === 'popup') {
      var deferred = jQuery.Deferred()

      var listener = function listener (event) {
        if (event.data !== '__ready__') {
          var fragment = getUrlFragment(event.data)
          Anvil.callback(parseFormUrlEncoded(fragment)).then(
            function (result) { deferred.resolve(result) },
            function (fault) { deferred.reject(fault) }
          )
          window.removeEventListener('message', listener, false)
        }
      }

      window.addEventListener('message', listener, false)
      window.open(this.uri(), 'anvil', popup(700, 500))

      return deferred.promise()

    // navigate the current window to the provider
    } else {
      window.location = this.uri()
    }
  }
}

Anvil.authorize = authorize

/**
 * Signout
 */

function signout (path) {
  // parse the window location
  var url = document.createElement('a')
  url.href = window.location.href
  url.pathname = path || '/'

  // set the destination
  Anvil.destination(path || false)

  // url to sign out of the auth server
  var location = issuer + '/signout?post_logout_redirect_uri=' +
    url.href + '&id_token_hint=' + Anvil.session.id_token

  // reset the session
  Anvil.reset()

  // "redirect"
  window.location = location
}

Anvil.signout = signout

/**
 * Destination
 *
 * Getter/setter location.pathname
 *
 *    // Set the destination
 *    Anvil.destination(location.pathname)
 *
 *    // Get the destination
 *    Anvil.destination()
 *
 *    // Clear the destination
 *    Anvil.destination(false)
 */

function destination (path) {
  if (path === false) {
    path = localStorage['anvil.connect.destination']
    delete localStorage['anvil.connect.destination']
    return path
  } else if (path) {
    localStorage['anvil.connect.destination'] = path
  } else {
    return localStorage['anvil.connect.destination']
  }
}

Anvil.destination = destination

/**
 * Check Session
 *
 * This is for use by the RP iframe, as specified by
 * OpenID Connect Session Management 1.0 - draft 23
 *
 * http://openid.net/specs/openid-connect-session-1_0.html
 */

function checkSession (id) {
  var targetOrigin = this.issuer
  var message = this.params.client_id + ' ' + this.sessionState
  var w = window.parent.document.getElementById(id).contentWindow
  w.postMessage(message, targetOrigin)
}

Anvil.checkSession = checkSession

/**
 * Update Session
 */

function updateSession (event) {
  if (event.key === 'anvil.connect') {
    Anvil.deserialize()
  }
}

Anvil.updateSession = updateSession
window.addEventListener('storage', updateSession, true)

/**
 * Is Authenticated
 */

function isAuthenticated () {
  return (Anvil.session.id_token)
}

Anvil.isAuthenticated = isAuthenticated

/**
 * Signing Key
 */

function getKeys () {
  function success (response) {
    setJWK(response && response.keys)
  }

  function failure (fault) {
    reject(fault)
  }

  return fetch(issuer + '/jwks', {
    method: 'GET',
    mode: 'cors'
  })
  .then(function(response) { return response.json()} )
  .then(success)
  .catch(failure)
}

Anvil.getKeys = getKeys

/**
 * Reinstate an existing session
 */

Anvil.deserialize()

/**
 * Export
 */

module.exports = Anvil
