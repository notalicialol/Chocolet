"use strict";

/**
 * Module dependencies.
 */

// eslint-disable-next-line node/no-deprecated-api
const {
  parse,
  format,
  resolve
} = require('url');
const Stream = require('stream');
const https = require('https');
const http = require('http');
const fs = require('fs');
const zlib = require('zlib');
const util = require('util');
const qs = require('qs');
const mime = require('mime');
let methods = require('methods');
const FormData = require('form-data');
const formidable = require('formidable');
const debug = require('debug')('superagent');
const CookieJar = require('cookiejar');
const semverGte = require('semver/functions/gte');
const safeStringify = require('fast-safe-stringify');
const utils = require('../utils');
const RequestBase = require('../request-base');
const {
  unzip
} = require('./unzip');
const Response = require('./response');
const {
  mixin,
  hasOwn
} = utils;
let http2;
if (semverGte(process.version, 'v10.10.0')) http2 = require('./http2wrapper');
function request(method, url) {
  // callback
  if (typeof url === 'function') {
    return new exports.Request('GET', method).end(url);
  }

  // url first
  if (arguments.length === 1) {
    return new exports.Request('GET', method);
  }
  return new exports.Request(method, url);
}
module.exports = request;
exports = module.exports;

/**
 * Expose `Request`.
 */

exports.Request = Request;

/**
 * Expose the agent function
 */

exports.agent = require('./agent');

/**
 * Noop.
 */

function noop() {}

/**
 * Expose `Response`.
 */

exports.Response = Response;

/**
 * Define "form" mime type.
 */

mime.define({
  'application/x-www-form-urlencoded': ['form', 'urlencoded', 'form-data']
}, true);

/**
 * Protocol map.
 */

exports.protocols = {
  'http:': http,
  'https:': https,
  'http2:': http2
};

/**
 * Default serialization map.
 *
 *     superagent.serialize['application/xml'] = function(obj){
 *       return 'generated xml here';
 *     };
 *
 */

exports.serialize = {
  'application/x-www-form-urlencoded': qs.stringify,
  'application/json': safeStringify
};

/**
 * Default parsers.
 *
 *     superagent.parse['application/xml'] = function(res, fn){
 *       fn(null, res);
 *     };
 *
 */

exports.parse = require('./parsers');

/**
 * Default buffering map. Can be used to set certain
 * response types to buffer/not buffer.
 *
 *     superagent.buffer['application/xml'] = true;
 */
exports.buffer = {};

/**
 * Initialize internal header tracking properties on a request instance.
 *
 * @param {Object} req the instance
 * @api private
 */
function _initHeaders(request_) {
  request_._header = {
    // coerces header names to lowercase
  };
  request_.header = {
    // preserves header name case
  };
}

/**
 * Initialize a new `Request` with the given `method` and `url`.
 *
 * @param {String} method
 * @param {String|Object} url
 * @api public
 */

function Request(method, url) {
  Stream.call(this);
  if (typeof url !== 'string') url = format(url);
  this._enableHttp2 = Boolean(process.env.HTTP2_TEST); // internal only
  this._agent = false;
  this._formData = null;
  this.method = method;
  this.url = url;
  _initHeaders(this);
  this.writable = true;
  this._redirects = 0;
  this.redirects(method === 'HEAD' ? 0 : 5);
  this.cookies = '';
  this.qs = {};
  this._query = [];
  this.qsRaw = this._query; // Unused, for backwards compatibility only
  this._redirectList = [];
  this._streamRequest = false;
  this._lookup = undefined;
  this.once('end', this.clearTimeout.bind(this));
}

/**
 * Inherit from `Stream` (which inherits from `EventEmitter`).
 * Mixin `RequestBase`.
 */
util.inherits(Request, Stream);
mixin(Request.prototype, RequestBase.prototype);

/**
 * Enable or Disable http2.
 *
 * Enable http2.
 *
 * ``` js
 * request.get('http://localhost/')
 *   .http2()
 *   .end(callback);
 *
 * request.get('http://localhost/')
 *   .http2(true)
 *   .end(callback);
 * ```
 *
 * Disable http2.
 *
 * ``` js
 * request = request.http2();
 * request.get('http://localhost/')
 *   .http2(false)
 *   .end(callback);
 * ```
 *
 * @param {Boolean} enable
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.http2 = function (bool) {
  if (exports.protocols['http2:'] === undefined) {
    throw new Error('superagent: this version of Node.js does not support http2');
  }
  this._enableHttp2 = bool === undefined ? true : bool;
  return this;
};

/**
 * Queue the given `file` as an attachment to the specified `field`,
 * with optional `options` (or filename).
 *
 * ``` js
 * request.post('http://localhost/upload')
 *   .attach('field', Buffer.from('<b>Hello world</b>'), 'hello.html')
 *   .end(callback);
 * ```
 *
 * A filename may also be used:
 *
 * ``` js
 * request.post('http://localhost/upload')
 *   .attach('files', 'image.jpg')
 *   .end(callback);
 * ```
 *
 * @param {String} field
 * @param {String|fs.ReadStream|Buffer} file
 * @param {String|Object} options
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.attach = function (field, file, options) {
  if (file) {
    if (this._data) {
      throw new Error("superagent can't mix .send() and .attach()");
    }
    let o = options || {};
    if (typeof options === 'string') {
      o = {
        filename: options
      };
    }
    if (typeof file === 'string') {
      if (!o.filename) o.filename = file;
      debug('creating `fs.ReadStream` instance for file: %s', file);
      file = fs.createReadStream(file);
      file.on('error', error => {
        const formData = this._getFormData();
        formData.emit('error', error);
      });
    } else if (!o.filename && file.path) {
      o.filename = file.path;
    }
    this._getFormData().append(field, file, o);
  }
  return this;
};
Request.prototype._getFormData = function () {
  if (!this._formData) {
    this._formData = new FormData();
    this._formData.on('error', error => {
      debug('FormData error', error);
      if (this.called) {
        // The request has already finished and the callback was called.
        // Silently ignore the error.
        return;
      }
      this.callback(error);
      this.abort();
    });
  }
  return this._formData;
};

/**
 * Gets/sets the `Agent` to use for this HTTP request. The default (if this
 * function is not called) is to opt out of connection pooling (`agent: false`).
 *
 * @param {http.Agent} agent
 * @return {http.Agent}
 * @api public
 */

Request.prototype.agent = function (agent) {
  if (arguments.length === 0) return this._agent;
  this._agent = agent;
  return this;
};

/**
 * Gets/sets the `lookup` function to use custom DNS resolver.
 *
 * @param {Function} lookup
 * @return {Function}
 * @api public
 */

Request.prototype.lookup = function (lookup) {
  if (arguments.length === 0) return this._lookup;
  this._lookup = lookup;
  return this;
};

/**
 * Set _Content-Type_ response header passed through `mime.getType()`.
 *
 * Examples:
 *
 *      request.post('/')
 *        .type('xml')
 *        .send(xmlstring)
 *        .end(callback);
 *
 *      request.post('/')
 *        .type('json')
 *        .send(jsonstring)
 *        .end(callback);
 *
 *      request.post('/')
 *        .type('application/json')
 *        .send(jsonstring)
 *        .end(callback);
 *
 * @param {String} type
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.type = function (type) {
  return this.set('Content-Type', type.includes('/') ? type : mime.getType(type));
};

/**
 * Set _Accept_ response header passed through `mime.getType()`.
 *
 * Examples:
 *
 *      superagent.types.json = 'application/json';
 *
 *      request.get('/agent')
 *        .accept('json')
 *        .end(callback);
 *
 *      request.get('/agent')
 *        .accept('application/json')
 *        .end(callback);
 *
 * @param {String} accept
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.accept = function (type) {
  return this.set('Accept', type.includes('/') ? type : mime.getType(type));
};

/**
 * Add query-string `val`.
 *
 * Examples:
 *
 *   request.get('/shoes')
 *     .query('size=10')
 *     .query({ color: 'blue' })
 *
 * @param {Object|String} val
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.query = function (value) {
  if (typeof value === 'string') {
    this._query.push(value);
  } else {
    Object.assign(this.qs, value);
  }
  return this;
};

/**
 * Write raw `data` / `encoding` to the socket.
 *
 * @param {Buffer|String} data
 * @param {String} encoding
 * @return {Boolean}
 * @api public
 */

Request.prototype.write = function (data, encoding) {
  const request_ = this.request();
  if (!this._streamRequest) {
    this._streamRequest = true;
  }
  return request_.write(data, encoding);
};

/**
 * Pipe the request body to `stream`.
 *
 * @param {Stream} stream
 * @param {Object} options
 * @return {Stream}
 * @api public
 */

Request.prototype.pipe = function (stream, options) {
  this.piped = true; // HACK...
  this.buffer(false);
  this.end();
  return this._pipeContinue(stream, options);
};
Request.prototype._pipeContinue = function (stream, options) {
  this.req.once('response', res => {
    // redirect
    if (isRedirect(res.statusCode) && this._redirects++ !== this._maxRedirects) {
      return this._redirect(res) === this ? this._pipeContinue(stream, options) : undefined;
    }
    this.res = res;
    this._emitResponse();
    if (this._aborted) return;
    if (this._shouldUnzip(res)) {
      const unzipObject = zlib.createUnzip();
      unzipObject.on('error', error => {
        if (error && error.code === 'Z_BUF_ERROR') {
          // unexpected end of file is ignored by browsers and curl
          stream.emit('end');
          return;
        }
        stream.emit('error', error);
      });
      res.pipe(unzipObject).pipe(stream, options);
      // don't emit 'end' until unzipObject has completed writing all its data.
      unzipObject.once('end', () => this.emit('end'));
    } else {
      res.pipe(stream, options);
      res.once('end', () => this.emit('end'));
    }
  });
  return stream;
};

/**
 * Enable / disable buffering.
 *
 * @return {Boolean} [val]
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.buffer = function (value) {
  this._buffer = value !== false;
  return this;
};

/**
 * Redirect to `url
 *
 * @param {IncomingMessage} res
 * @return {Request} for chaining
 * @api private
 */

Request.prototype._redirect = function (res) {
  let url = res.headers.location;
  if (!url) {
    return this.callback(new Error('No location header for redirect'), res);
  }
  debug('redirect %s -> %s', this.url, url);

  // location
  url = resolve(this.url, url);

  // ensure the response is being consumed
  // this is required for Node v0.10+
  res.resume();
  let headers = this.req.getHeaders ? this.req.getHeaders() : this.req._headers;
  const changesOrigin = parse(url).host !== parse(this.url).host;

  // implementation of 302 following defacto standard
  if (res.statusCode === 301 || res.statusCode === 302) {
    // strip Content-* related fields
    // in case of POST etc
    headers = utils.cleanHeader(headers, changesOrigin);

    // force GET
    this.method = this.method === 'HEAD' ? 'HEAD' : 'GET';

    // clear data
    this._data = null;
  }

  // 303 is always GET
  if (res.statusCode === 303) {
    // strip Content-* related fields
    // in case of POST etc
    headers = utils.cleanHeader(headers, changesOrigin);

    // force method
    this.method = 'GET';

    // clear data
    this._data = null;
  }

  // 307 preserves method
  // 308 preserves method
  delete headers.host;
  delete this.req;
  delete this._formData;

  // remove all add header except User-Agent
  _initHeaders(this);

  // redirect
  this.res = res;
  this._endCalled = false;
  this.url = url;
  this.qs = {};
  this._query.length = 0;
  this.set(headers);
  this._emitRedirect();
  this._redirectList.push(this.url);
  this.end(this._callback);
  return this;
};

/**
 * Set Authorization field value with `user` and `pass`.
 *
 * Examples:
 *
 *   .auth('tobi', 'learnboost')
 *   .auth('tobi:learnboost')
 *   .auth('tobi')
 *   .auth(accessToken, { type: 'bearer' })
 *
 * @param {String} user
 * @param {String} [pass]
 * @param {Object} [options] options with authorization type 'basic' or 'bearer' ('basic' is default)
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.auth = function (user, pass, options) {
  if (arguments.length === 1) pass = '';
  if (typeof pass === 'object' && pass !== null) {
    // pass is optional and can be replaced with options
    options = pass;
    pass = '';
  }
  if (!options) {
    options = {
      type: 'basic'
    };
  }
  const encoder = string => Buffer.from(string).toString('base64');
  return this._auth(user, pass, options, encoder);
};

/**
 * Set the certificate authority option for https request.
 *
 * @param {Buffer | Array} cert
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.ca = function (cert) {
  this._ca = cert;
  return this;
};

/**
 * Set the client certificate key option for https request.
 *
 * @param {Buffer | String} cert
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.key = function (cert) {
  this._key = cert;
  return this;
};

/**
 * Set the key, certificate, and CA certs of the client in PFX or PKCS12 format.
 *
 * @param {Buffer | String} cert
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.pfx = function (cert) {
  if (typeof cert === 'object' && !Buffer.isBuffer(cert)) {
    this._pfx = cert.pfx;
    this._passphrase = cert.passphrase;
  } else {
    this._pfx = cert;
  }
  return this;
};

/**
 * Set the client certificate option for https request.
 *
 * @param {Buffer | String} cert
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.cert = function (cert) {
  this._cert = cert;
  return this;
};

/**
 * Do not reject expired or invalid TLS certs.
 * sets `rejectUnauthorized=true`. Be warned that this allows MITM attacks.
 *
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.disableTLSCerts = function () {
  this._disableTLSCerts = true;
  return this;
};

/**
 * Return an http[s] request.
 *
 * @return {OutgoingMessage}
 * @api private
 */

// eslint-disable-next-line complexity
Request.prototype.request = function () {
  if (this.req) return this.req;
  const options = {};
  try {
    const query = qs.stringify(this.qs, {
      indices: false,
      strictNullHandling: true
    });
    if (query) {
      this.qs = {};
      this._query.push(query);
    }
    this._finalizeQueryString();
  } catch (err) {
    return this.emit('error', err);
  }
  let {
    url
  } = this;
  const retries = this._retries;

  // Capture backticks as-is from the final query string built above.
  // Note: this'll only find backticks entered in req.query(String)
  // calls, because qs.stringify unconditionally encodes backticks.
  let queryStringBackticks;
  if (url.includes('`')) {
    const queryStartIndex = url.indexOf('?');
    if (queryStartIndex !== -1) {
      const queryString = url.slice(queryStartIndex + 1);
      queryStringBackticks = queryString.match(/`|%60/g);
    }
  }

  // default to http://
  if (url.indexOf('http') !== 0) url = `http://${url}`;
  url = parse(url);

  // See https://github.com/ladjs/superagent/issues/1367
  if (queryStringBackticks) {
    let i = 0;
    url.query = url.query.replace(/%60/g, () => queryStringBackticks[i++]);
    url.search = `?${url.query}`;
    url.path = url.pathname + url.search;
  }

  // support unix sockets
  if (/^https?\+unix:/.test(url.protocol) === true) {
    // get the protocol
    url.protocol = `${url.protocol.split('+')[0]}:`;

    // get the socket, path
    const unixParts = url.path.match(/^([^/]+)(.+)$/);
    options.socketPath = unixParts[1].replace(/%2F/g, '/');
    url.path = unixParts[2];
  }

  // Override IP address of a hostname
  if (this._connectOverride) {
    const {
      hostname
    } = url;
    const match = hostname in this._connectOverride ? this._connectOverride[hostname] : this._connectOverride['*'];
    if (match) {
      // backup the real host
      if (!this._header.host) {
        this.set('host', url.host);
      }
      let newHost;
      let newPort;
      if (typeof match === 'object') {
        newHost = match.host;
        newPort = match.port;
      } else {
        newHost = match;
        newPort = url.port;
      }

      // wrap [ipv6]
      url.host = /:/.test(newHost) ? `[${newHost}]` : newHost;
      if (newPort) {
        url.host += `:${newPort}`;
        url.port = newPort;
      }
      url.hostname = newHost;
    }
  }

  // options
  options.method = this.method;
  options.port = url.port;
  options.path = url.path;
  options.host = url.hostname;
  options.ca = this._ca;
  options.key = this._key;
  options.pfx = this._pfx;
  options.cert = this._cert;
  options.passphrase = this._passphrase;
  options.agent = this._agent;
  options.lookup = this._lookup;
  options.rejectUnauthorized = typeof this._disableTLSCerts === 'boolean' ? !this._disableTLSCerts : process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0';

  // Allows request.get('https://1.2.3.4/').set('Host', 'example.com')
  if (this._header.host) {
    options.servername = this._header.host.replace(/:\d+$/, '');
  }
  if (this._trustLocalhost && /^(?:localhost|127\.0\.0\.\d+|(0*:)+:0*1)$/.test(url.hostname)) {
    options.rejectUnauthorized = false;
  }

  // initiate request
  const module_ = this._enableHttp2 ? exports.protocols['http2:'].setProtocol(url.protocol) : exports.protocols[url.protocol];

  // request
  this.req = module_.request(options);
  const {
    req
  } = this;

  // set tcp no delay
  req.setNoDelay(true);
  if (options.method !== 'HEAD') {
    req.setHeader('Accept-Encoding', 'gzip, deflate');
  }
  this.protocol = url.protocol;
  this.host = url.host;

  // expose events
  req.once('drain', () => {
    this.emit('drain');
  });
  req.on('error', error => {
    // flag abortion here for out timeouts
    // because node will emit a faux-error "socket hang up"
    // when request is aborted before a connection is made
    if (this._aborted) return;
    // if not the same, we are in the **old** (cancelled) request,
    // so need to continue (same as for above)
    if (this._retries !== retries) return;
    // if we've received a response then we don't want to let
    // an error in the request blow up the response
    if (this.response) return;
    this.callback(error);
  });

  // auth
  if (url.auth) {
    const auth = url.auth.split(':');
    this.auth(auth[0], auth[1]);
  }
  if (this.username && this.password) {
    this.auth(this.username, this.password);
  }
  for (const key in this.header) {
    if (hasOwn(this.header, key)) req.setHeader(key, this.header[key]);
  }

  // add cookies
  if (this.cookies) {
    if (hasOwn(this._header, 'cookie')) {
      // merge
      const temporaryJar = new CookieJar.CookieJar();
      temporaryJar.setCookies(this._header.cookie.split('; '));
      temporaryJar.setCookies(this.cookies.split('; '));
      req.setHeader('Cookie', temporaryJar.getCookies(CookieJar.CookieAccessInfo.All).toValueString());
    } else {
      req.setHeader('Cookie', this.cookies);
    }
  }
  return req;
};

/**
 * Invoke the callback with `err` and `res`
 * and handle arity check.
 *
 * @param {Error} err
 * @param {Response} res
 * @api private
 */

Request.prototype.callback = function (error, res) {
  if (this._shouldRetry(error, res)) {
    return this._retry();
  }

  // Avoid the error which is emitted from 'socket hang up' to cause the fn undefined error on JS runtime.
  const fn = this._callback || noop;
  this.clearTimeout();
  if (this.called) return console.warn('superagent: double callback bug');
  this.called = true;
  if (!error) {
    try {
      if (!this._isResponseOK(res)) {
        let message = 'Unsuccessful HTTP response';
        if (res) {
          message = http.STATUS_CODES[res.status] || message;
        }
        error = new Error(message);
        error.status = res ? res.status : undefined;
      }
    } catch (err) {
      error = err;
      error.status = error.status || (res ? res.status : undefined);
    }
  }

  // It's important that the callback is called outside try/catch
  // to avoid double callback
  if (!error) {
    return fn(null, res);
  }
  error.response = res;
  if (this._maxRetries) error.retries = this._retries - 1;

  // only emit error event if there is a listener
  // otherwise we assume the callback to `.end()` will get the error
  if (error && this.listeners('error').length > 0) {
    this.emit('error', error);
  }
  fn(error, res);
};

/**
 * Check if `obj` is a host object,
 *
 * @param {Object} obj host object
 * @return {Boolean} is a host object
 * @api private
 */
Request.prototype._isHost = function (object) {
  return Buffer.isBuffer(object) || object instanceof Stream || object instanceof FormData;
};

/**
 * Initiate request, invoking callback `fn(err, res)`
 * with an instanceof `Response`.
 *
 * @param {Function} fn
 * @return {Request} for chaining
 * @api public
 */

Request.prototype._emitResponse = function (body, files) {
  const response = new Response(this);
  this.response = response;
  response.redirects = this._redirectList;
  if (undefined !== body) {
    response.body = body;
  }
  response.files = files;
  if (this._endCalled) {
    response.pipe = function () {
      throw new Error("end() has already been called, so it's too late to start piping");
    };
  }
  this.emit('response', response);
  return response;
};

/**
 * Emit `redirect` event, passing an instanceof `Response`.
 *
 * @api private
 */

Request.prototype._emitRedirect = function () {
  const response = new Response(this);
  response.redirects = this._redirectList;
  this.emit('redirect', response);
};
Request.prototype.end = function (fn) {
  this.request();
  debug('%s %s', this.method, this.url);
  if (this._endCalled) {
    throw new Error('.end() was called twice. This is not supported in superagent');
  }
  this._endCalled = true;

  // store callback
  this._callback = fn || noop;
  this._end();
};
Request.prototype._end = function () {
  if (this._aborted) return this.callback(new Error('The request has been aborted even before .end() was called'));
  let data = this._data;
  const {
    req
  } = this;
  const {
    method
  } = this;
  this._setTimeouts();

  // body
  if (method !== 'HEAD' && !req._headerSent) {
    // serialize stuff
    if (typeof data !== 'string') {
      let contentType = req.getHeader('Content-Type');
      // Parse out just the content type from the header (ignore the charset)
      if (contentType) contentType = contentType.split(';')[0];
      let serialize = this._serializer || exports.serialize[contentType];
      if (!serialize && isJSON(contentType)) {
        serialize = exports.serialize['application/json'];
      }
      if (serialize) data = serialize(data);
    }

    // content-length
    if (data && !req.getHeader('Content-Length')) {
      req.setHeader('Content-Length', Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data));
    }
  }

  // response
  // eslint-disable-next-line complexity
  req.once('response', res => {
    debug('%s %s -> %s', this.method, this.url, res.statusCode);
    if (this._responseTimeoutTimer) {
      clearTimeout(this._responseTimeoutTimer);
    }
    if (this.piped) {
      return;
    }
    const max = this._maxRedirects;
    const mime = utils.type(res.headers['content-type'] || '') || 'text/plain';
    let type = mime.split('/')[0];
    if (type) type = type.toLowerCase().trim();
    const multipart = type === 'multipart';
    const redirect = isRedirect(res.statusCode);
    const responseType = this._responseType;
    this.res = res;

    // redirect
    if (redirect && this._redirects++ !== max) {
      return this._redirect(res);
    }
    if (this.method === 'HEAD') {
      this.emit('end');
      this.callback(null, this._emitResponse());
      return;
    }

    // zlib support
    if (this._shouldUnzip(res)) {
      unzip(req, res);
    }
    let buffer = this._buffer;
    if (buffer === undefined && mime in exports.buffer) {
      buffer = Boolean(exports.buffer[mime]);
    }
    let parser = this._parser;
    if (undefined === buffer && parser) {
      console.warn("A custom superagent parser has been set, but buffering strategy for the parser hasn't been configured. Call `req.buffer(true or false)` or set `superagent.buffer[mime] = true or false`");
      buffer = true;
    }
    if (!parser) {
      if (responseType) {
        parser = exports.parse.image; // It's actually a generic Buffer
        buffer = true;
      } else if (multipart) {
        const form = formidable.formidable();
        parser = form.parse.bind(form);
        buffer = true;
      } else if (isBinary(mime)) {
        parser = exports.parse.image;
        buffer = true; // For backwards-compatibility buffering default is ad-hoc MIME-dependent
      } else if (exports.parse[mime]) {
        parser = exports.parse[mime];
      } else if (type === 'text') {
        parser = exports.parse.text;
        buffer = buffer !== false;
        // everyone wants their own white-labeled json
      } else if (isJSON(mime)) {
        parser = exports.parse['application/json'];
        buffer = buffer !== false;
      } else if (buffer) {
        parser = exports.parse.text;
      } else if (undefined === buffer) {
        parser = exports.parse.image; // It's actually a generic Buffer
        buffer = true;
      }
    }

    // by default only buffer text/*, json and messed up thing from hell
    if (undefined === buffer && isText(mime) || isJSON(mime)) {
      buffer = true;
    }
    this._resBuffered = buffer;
    let parserHandlesEnd = false;
    if (buffer) {
      // Protectiona against zip bombs and other nuisance
      let responseBytesLeft = this._maxResponseSize || 200000000;
      res.on('data', buf => {
        responseBytesLeft -= buf.byteLength || buf.length > 0 ? buf.length : 0;
        if (responseBytesLeft < 0) {
          // This will propagate through error event
          const error = new Error('Maximum response size reached');
          error.code = 'ETOOLARGE';
          // Parsers aren't required to observe error event,
          // so would incorrectly report success
          parserHandlesEnd = false;
          // Will not emit error event
          res.destroy(error);
          // so we do callback now
          this.callback(error, null);
        }
      });
    }
    if (parser) {
      try {
        // Unbuffered parsers are supposed to emit response early,
        // which is weird BTW, because response.body won't be there.
        parserHandlesEnd = buffer;
        parser(res, (error, object, files) => {
          if (this.timedout) {
            // Timeout has already handled all callbacks
            return;
          }

          // Intentional (non-timeout) abort is supposed to preserve partial response,
          // even if it doesn't parse.
          if (error && !this._aborted) {
            return this.callback(error);
          }
          if (parserHandlesEnd) {
            if (multipart) {
              // formidable v3 always returns an array with the value in it
              // so we need to flatten it
              if (object) {
                for (const key in object) {
                  const value = object[key];
                  if (Array.isArray(value) && value.length === 1) {
                    object[key] = value[0];
                  } else {
                    object[key] = value;
                  }
                }
              }
              if (files) {
                for (const key in files) {
                  const value = files[key];
                  if (Array.isArray(value) && value.length === 1) {
                    files[key] = value[0];
                  } else {
                    files[key] = value;
                  }
                }
              }
            }
            this.emit('end');
            this.callback(null, this._emitResponse(object, files));
          }
        });
      } catch (err) {
        this.callback(err);
        return;
      }
    }
    this.res = res;

    // unbuffered
    if (!buffer) {
      debug('unbuffered %s %s', this.method, this.url);
      this.callback(null, this._emitResponse());
      if (multipart) return; // allow multipart to handle end event
      res.once('end', () => {
        debug('end %s %s', this.method, this.url);
        this.emit('end');
      });
      return;
    }

    // terminating events
    res.once('error', error => {
      parserHandlesEnd = false;
      this.callback(error, null);
    });
    if (!parserHandlesEnd) res.once('end', () => {
      debug('end %s %s', this.method, this.url);
      // TODO: unless buffering emit earlier to stream
      this.emit('end');
      this.callback(null, this._emitResponse());
    });
  });
  this.emit('request', this);
  const getProgressMonitor = () => {
    const lengthComputable = true;
    const total = req.getHeader('Content-Length');
    let loaded = 0;
    const progress = new Stream.Transform();
    progress._transform = (chunk, encoding, callback) => {
      loaded += chunk.length;
      this.emit('progress', {
        direction: 'upload',
        lengthComputable,
        loaded,
        total
      });
      callback(null, chunk);
    };
    return progress;
  };
  const bufferToChunks = buffer => {
    const chunkSize = 16 * 1024; // default highWaterMark value
    const chunking = new Stream.Readable();
    const totalLength = buffer.length;
    const remainder = totalLength % chunkSize;
    const cutoff = totalLength - remainder;
    for (let i = 0; i < cutoff; i += chunkSize) {
      const chunk = buffer.slice(i, i + chunkSize);
      chunking.push(chunk);
    }
    if (remainder > 0) {
      const remainderBuffer = buffer.slice(-remainder);
      chunking.push(remainderBuffer);
    }
    chunking.push(null); // no more data

    return chunking;
  };

  // if a FormData instance got created, then we send that as the request body
  const formData = this._formData;
  if (formData) {
    // set headers
    const headers = formData.getHeaders();
    for (const i in headers) {
      if (hasOwn(headers, i)) {
        debug('setting FormData header: "%s: %s"', i, headers[i]);
        req.setHeader(i, headers[i]);
      }
    }

    // attempt to get "Content-Length" header
    formData.getLength((error, length) => {
      // TODO: Add chunked encoding when no length (if err)
      if (error) debug('formData.getLength had error', error, length);
      debug('got FormData Content-Length: %s', length);
      if (typeof length === 'number') {
        req.setHeader('Content-Length', length);
      }
      formData.pipe(getProgressMonitor()).pipe(req);
    });
  } else if (Buffer.isBuffer(data)) {
    bufferToChunks(data).pipe(getProgressMonitor()).pipe(req);
  } else {
    req.end(data);
  }
};

// Check whether response has a non-0-sized gzip-encoded body
Request.prototype._shouldUnzip = res => {
  if (res.statusCode === 204 || res.statusCode === 304) {
    // These aren't supposed to have any body
    return false;
  }

  // header content is a string, and distinction between 0 and no information is crucial
  if (res.headers['content-length'] === '0') {
    // We know that the body is empty (unfortunately, this check does not cover chunked encoding)
    return false;
  }

  // console.log(res);
  return /^\s*(?:deflate|gzip)\s*$/.test(res.headers['content-encoding']);
};

/**
 * Overrides DNS for selected hostnames. Takes object mapping hostnames to IP addresses.
 *
 * When making a request to a URL with a hostname exactly matching a key in the object,
 * use the given IP address to connect, instead of using DNS to resolve the hostname.
 *
 * A special host `*` matches every hostname (keep redirects in mind!)
 *
 *      request.connect({
 *        'test.example.com': '127.0.0.1',
 *        'ipv6.example.com': '::1',
 *      })
 */
Request.prototype.connect = function (connectOverride) {
  if (typeof connectOverride === 'string') {
    this._connectOverride = {
      '*': connectOverride
    };
  } else if (typeof connectOverride === 'object') {
    this._connectOverride = connectOverride;
  } else {
    this._connectOverride = undefined;
  }
  return this;
};
Request.prototype.trustLocalhost = function (toggle) {
  this._trustLocalhost = toggle === undefined ? true : toggle;
  return this;
};

// generate HTTP verb methods
if (!methods.includes('del')) {
  // create a copy so we don't cause conflicts with
  // other packages using the methods package and
  // npm 3.x
  methods = [...methods];
  methods.push('del');
}
for (let method of methods) {
  const name = method;
  method = method === 'del' ? 'delete' : method;
  method = method.toUpperCase();
  request[name] = (url, data, fn) => {
    const request_ = request(method, url);
    if (typeof data === 'function') {
      fn = data;
      data = null;
    }
    if (data) {
      if (method === 'GET' || method === 'HEAD') {
        request_.query(data);
      } else {
        request_.send(data);
      }
    }
    if (fn) request_.end(fn);
    return request_;
  };
}

/**
 * Check if `mime` is text and should be buffered.
 *
 * @param {String} mime
 * @return {Boolean}
 * @api public
 */

function isText(mime) {
  const parts = mime.split('/');
  let type = parts[0];
  if (type) type = type.toLowerCase().trim();
  let subtype = parts[1];
  if (subtype) subtype = subtype.toLowerCase().trim();
  return type === 'text' || subtype === 'x-www-form-urlencoded';
}

// This is not a catchall, but a start. It might be useful
// in the long run to have file that includes all binary
// content types from https://www.iana.org/assignments/media-types/media-types.xhtml
function isBinary(mime) {
  let [registry, name] = mime.split('/');
  if (registry) registry = registry.toLowerCase().trim();
  if (name) name = name.toLowerCase().trim();
  return ['audio', 'font', 'image', 'video'].includes(registry) || ['gz', 'gzip'].includes(name);
}

/**
 * Check if `mime` is json or has +json structured syntax suffix.
 *
 * @param {String} mime
 * @return {Boolean}
 * @api private
 */

function isJSON(mime) {
  // should match /json or +json
  // but not /json-seq
  return /[/+]json($|[^-\w])/i.test(mime);
}

/**
 * Check if we should follow the redirect `code`.
 *
 * @param {Number} code
 * @return {Boolean}
 * @api private
 */

function isRedirect(code) {
  return [301, 302, 303, 305, 307, 308].includes(code);
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJwYXJzZSIsImZvcm1hdCIsInJlc29sdmUiLCJyZXF1aXJlIiwiU3RyZWFtIiwiaHR0cHMiLCJodHRwIiwiZnMiLCJ6bGliIiwidXRpbCIsInFzIiwibWltZSIsIm1ldGhvZHMiLCJGb3JtRGF0YSIsImZvcm1pZGFibGUiLCJkZWJ1ZyIsIkNvb2tpZUphciIsInNlbXZlckd0ZSIsInNhZmVTdHJpbmdpZnkiLCJ1dGlscyIsIlJlcXVlc3RCYXNlIiwidW56aXAiLCJSZXNwb25zZSIsIm1peGluIiwiaGFzT3duIiwiaHR0cDIiLCJwcm9jZXNzIiwidmVyc2lvbiIsInJlcXVlc3QiLCJtZXRob2QiLCJ1cmwiLCJleHBvcnRzIiwiUmVxdWVzdCIsImVuZCIsImFyZ3VtZW50cyIsImxlbmd0aCIsIm1vZHVsZSIsImFnZW50Iiwibm9vcCIsImRlZmluZSIsInByb3RvY29scyIsInNlcmlhbGl6ZSIsInN0cmluZ2lmeSIsImJ1ZmZlciIsIl9pbml0SGVhZGVycyIsInJlcXVlc3RfIiwiX2hlYWRlciIsImhlYWRlciIsImNhbGwiLCJfZW5hYmxlSHR0cDIiLCJCb29sZWFuIiwiZW52IiwiSFRUUDJfVEVTVCIsIl9hZ2VudCIsIl9mb3JtRGF0YSIsIndyaXRhYmxlIiwiX3JlZGlyZWN0cyIsInJlZGlyZWN0cyIsImNvb2tpZXMiLCJfcXVlcnkiLCJxc1JhdyIsIl9yZWRpcmVjdExpc3QiLCJfc3RyZWFtUmVxdWVzdCIsIl9sb29rdXAiLCJ1bmRlZmluZWQiLCJvbmNlIiwiY2xlYXJUaW1lb3V0IiwiYmluZCIsImluaGVyaXRzIiwicHJvdG90eXBlIiwiYm9vbCIsIkVycm9yIiwiYXR0YWNoIiwiZmllbGQiLCJmaWxlIiwib3B0aW9ucyIsIl9kYXRhIiwibyIsImZpbGVuYW1lIiwiY3JlYXRlUmVhZFN0cmVhbSIsIm9uIiwiZXJyb3IiLCJmb3JtRGF0YSIsIl9nZXRGb3JtRGF0YSIsImVtaXQiLCJwYXRoIiwiYXBwZW5kIiwiY2FsbGVkIiwiY2FsbGJhY2siLCJhYm9ydCIsImxvb2t1cCIsInR5cGUiLCJzZXQiLCJpbmNsdWRlcyIsImdldFR5cGUiLCJhY2NlcHQiLCJxdWVyeSIsInZhbHVlIiwicHVzaCIsIk9iamVjdCIsImFzc2lnbiIsIndyaXRlIiwiZGF0YSIsImVuY29kaW5nIiwicGlwZSIsInN0cmVhbSIsInBpcGVkIiwiX3BpcGVDb250aW51ZSIsInJlcSIsInJlcyIsImlzUmVkaXJlY3QiLCJzdGF0dXNDb2RlIiwiX21heFJlZGlyZWN0cyIsIl9yZWRpcmVjdCIsIl9lbWl0UmVzcG9uc2UiLCJfYWJvcnRlZCIsIl9zaG91bGRVbnppcCIsInVuemlwT2JqZWN0IiwiY3JlYXRlVW56aXAiLCJjb2RlIiwiX2J1ZmZlciIsImhlYWRlcnMiLCJsb2NhdGlvbiIsInJlc3VtZSIsImdldEhlYWRlcnMiLCJfaGVhZGVycyIsImNoYW5nZXNPcmlnaW4iLCJob3N0IiwiY2xlYW5IZWFkZXIiLCJfZW5kQ2FsbGVkIiwiX2VtaXRSZWRpcmVjdCIsIl9jYWxsYmFjayIsImF1dGgiLCJ1c2VyIiwicGFzcyIsImVuY29kZXIiLCJzdHJpbmciLCJCdWZmZXIiLCJmcm9tIiwidG9TdHJpbmciLCJfYXV0aCIsImNhIiwiY2VydCIsIl9jYSIsImtleSIsIl9rZXkiLCJwZngiLCJpc0J1ZmZlciIsIl9wZngiLCJfcGFzc3BocmFzZSIsInBhc3NwaHJhc2UiLCJfY2VydCIsImRpc2FibGVUTFNDZXJ0cyIsIl9kaXNhYmxlVExTQ2VydHMiLCJpbmRpY2VzIiwic3RyaWN0TnVsbEhhbmRsaW5nIiwiX2ZpbmFsaXplUXVlcnlTdHJpbmciLCJlcnIiLCJyZXRyaWVzIiwiX3JldHJpZXMiLCJxdWVyeVN0cmluZ0JhY2t0aWNrcyIsInF1ZXJ5U3RhcnRJbmRleCIsImluZGV4T2YiLCJxdWVyeVN0cmluZyIsInNsaWNlIiwibWF0Y2giLCJpIiwicmVwbGFjZSIsInNlYXJjaCIsInBhdGhuYW1lIiwidGVzdCIsInByb3RvY29sIiwic3BsaXQiLCJ1bml4UGFydHMiLCJzb2NrZXRQYXRoIiwiX2Nvbm5lY3RPdmVycmlkZSIsImhvc3RuYW1lIiwibmV3SG9zdCIsIm5ld1BvcnQiLCJwb3J0IiwicmVqZWN0VW5hdXRob3JpemVkIiwiTk9ERV9UTFNfUkVKRUNUX1VOQVVUSE9SSVpFRCIsInNlcnZlcm5hbWUiLCJfdHJ1c3RMb2NhbGhvc3QiLCJtb2R1bGVfIiwic2V0UHJvdG9jb2wiLCJzZXROb0RlbGF5Iiwic2V0SGVhZGVyIiwicmVzcG9uc2UiLCJ1c2VybmFtZSIsInBhc3N3b3JkIiwidGVtcG9yYXJ5SmFyIiwic2V0Q29va2llcyIsImNvb2tpZSIsImdldENvb2tpZXMiLCJDb29raWVBY2Nlc3NJbmZvIiwiQWxsIiwidG9WYWx1ZVN0cmluZyIsIl9zaG91bGRSZXRyeSIsIl9yZXRyeSIsImZuIiwiY29uc29sZSIsIndhcm4iLCJfaXNSZXNwb25zZU9LIiwibWVzc2FnZSIsIlNUQVRVU19DT0RFUyIsInN0YXR1cyIsIl9tYXhSZXRyaWVzIiwibGlzdGVuZXJzIiwiX2lzSG9zdCIsIm9iamVjdCIsImJvZHkiLCJmaWxlcyIsIl9lbmQiLCJfc2V0VGltZW91dHMiLCJfaGVhZGVyU2VudCIsImNvbnRlbnRUeXBlIiwiZ2V0SGVhZGVyIiwiX3NlcmlhbGl6ZXIiLCJpc0pTT04iLCJieXRlTGVuZ3RoIiwiX3Jlc3BvbnNlVGltZW91dFRpbWVyIiwibWF4IiwidG9Mb3dlckNhc2UiLCJ0cmltIiwibXVsdGlwYXJ0IiwicmVkaXJlY3QiLCJyZXNwb25zZVR5cGUiLCJfcmVzcG9uc2VUeXBlIiwicGFyc2VyIiwiX3BhcnNlciIsImltYWdlIiwiZm9ybSIsImlzQmluYXJ5IiwidGV4dCIsImlzVGV4dCIsIl9yZXNCdWZmZXJlZCIsInBhcnNlckhhbmRsZXNFbmQiLCJyZXNwb25zZUJ5dGVzTGVmdCIsIl9tYXhSZXNwb25zZVNpemUiLCJidWYiLCJkZXN0cm95IiwidGltZWRvdXQiLCJBcnJheSIsImlzQXJyYXkiLCJnZXRQcm9ncmVzc01vbml0b3IiLCJsZW5ndGhDb21wdXRhYmxlIiwidG90YWwiLCJsb2FkZWQiLCJwcm9ncmVzcyIsIlRyYW5zZm9ybSIsIl90cmFuc2Zvcm0iLCJjaHVuayIsImRpcmVjdGlvbiIsImJ1ZmZlclRvQ2h1bmtzIiwiY2h1bmtTaXplIiwiY2h1bmtpbmciLCJSZWFkYWJsZSIsInRvdGFsTGVuZ3RoIiwicmVtYWluZGVyIiwiY3V0b2ZmIiwicmVtYWluZGVyQnVmZmVyIiwiZ2V0TGVuZ3RoIiwiY29ubmVjdCIsImNvbm5lY3RPdmVycmlkZSIsInRydXN0TG9jYWxob3N0IiwidG9nZ2xlIiwibmFtZSIsInRvVXBwZXJDYXNlIiwic2VuZCIsInBhcnRzIiwic3VidHlwZSIsInJlZ2lzdHJ5Il0sInNvdXJjZXMiOlsiLi4vLi4vc3JjL25vZGUvaW5kZXguanMiXSwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBNb2R1bGUgZGVwZW5kZW5jaWVzLlxuICovXG5cbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBub2RlL25vLWRlcHJlY2F0ZWQtYXBpXG5jb25zdCB7IHBhcnNlLCBmb3JtYXQsIHJlc29sdmUgfSA9IHJlcXVpcmUoJ3VybCcpO1xuY29uc3QgU3RyZWFtID0gcmVxdWlyZSgnc3RyZWFtJyk7XG5jb25zdCBodHRwcyA9IHJlcXVpcmUoJ2h0dHBzJyk7XG5jb25zdCBodHRwID0gcmVxdWlyZSgnaHR0cCcpO1xuY29uc3QgZnMgPSByZXF1aXJlKCdmcycpO1xuY29uc3QgemxpYiA9IHJlcXVpcmUoJ3psaWInKTtcbmNvbnN0IHV0aWwgPSByZXF1aXJlKCd1dGlsJyk7XG5jb25zdCBxcyA9IHJlcXVpcmUoJ3FzJyk7XG5jb25zdCBtaW1lID0gcmVxdWlyZSgnbWltZScpO1xubGV0IG1ldGhvZHMgPSByZXF1aXJlKCdtZXRob2RzJyk7XG5jb25zdCBGb3JtRGF0YSA9IHJlcXVpcmUoJ2Zvcm0tZGF0YScpO1xuY29uc3QgZm9ybWlkYWJsZSA9IHJlcXVpcmUoJ2Zvcm1pZGFibGUnKTtcbmNvbnN0IGRlYnVnID0gcmVxdWlyZSgnZGVidWcnKSgnc3VwZXJhZ2VudCcpO1xuY29uc3QgQ29va2llSmFyID0gcmVxdWlyZSgnY29va2llamFyJyk7XG5jb25zdCBzZW12ZXJHdGUgPSByZXF1aXJlKCdzZW12ZXIvZnVuY3Rpb25zL2d0ZScpO1xuY29uc3Qgc2FmZVN0cmluZ2lmeSA9IHJlcXVpcmUoJ2Zhc3Qtc2FmZS1zdHJpbmdpZnknKTtcblxuY29uc3QgdXRpbHMgPSByZXF1aXJlKCcuLi91dGlscycpO1xuY29uc3QgUmVxdWVzdEJhc2UgPSByZXF1aXJlKCcuLi9yZXF1ZXN0LWJhc2UnKTtcbmNvbnN0IHsgdW56aXAgfSA9IHJlcXVpcmUoJy4vdW56aXAnKTtcbmNvbnN0IFJlc3BvbnNlID0gcmVxdWlyZSgnLi9yZXNwb25zZScpO1xuXG5jb25zdCB7IG1peGluLCBoYXNPd24gfSA9IHV0aWxzO1xuXG5sZXQgaHR0cDI7XG5cbmlmIChzZW12ZXJHdGUocHJvY2Vzcy52ZXJzaW9uLCAndjEwLjEwLjAnKSkgaHR0cDIgPSByZXF1aXJlKCcuL2h0dHAyd3JhcHBlcicpO1xuXG5mdW5jdGlvbiByZXF1ZXN0KG1ldGhvZCwgdXJsKSB7XG4gIC8vIGNhbGxiYWNrXG4gIGlmICh0eXBlb2YgdXJsID09PSAnZnVuY3Rpb24nKSB7XG4gICAgcmV0dXJuIG5ldyBleHBvcnRzLlJlcXVlc3QoJ0dFVCcsIG1ldGhvZCkuZW5kKHVybCk7XG4gIH1cblxuICAvLyB1cmwgZmlyc3RcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPT09IDEpIHtcbiAgICByZXR1cm4gbmV3IGV4cG9ydHMuUmVxdWVzdCgnR0VUJywgbWV0aG9kKTtcbiAgfVxuXG4gIHJldHVybiBuZXcgZXhwb3J0cy5SZXF1ZXN0KG1ldGhvZCwgdXJsKTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSByZXF1ZXN0O1xuZXhwb3J0cyA9IG1vZHVsZS5leHBvcnRzO1xuXG4vKipcbiAqIEV4cG9zZSBgUmVxdWVzdGAuXG4gKi9cblxuZXhwb3J0cy5SZXF1ZXN0ID0gUmVxdWVzdDtcblxuLyoqXG4gKiBFeHBvc2UgdGhlIGFnZW50IGZ1bmN0aW9uXG4gKi9cblxuZXhwb3J0cy5hZ2VudCA9IHJlcXVpcmUoJy4vYWdlbnQnKTtcblxuLyoqXG4gKiBOb29wLlxuICovXG5cbmZ1bmN0aW9uIG5vb3AoKSB7fVxuXG4vKipcbiAqIEV4cG9zZSBgUmVzcG9uc2VgLlxuICovXG5cbmV4cG9ydHMuUmVzcG9uc2UgPSBSZXNwb25zZTtcblxuLyoqXG4gKiBEZWZpbmUgXCJmb3JtXCIgbWltZSB0eXBlLlxuICovXG5cbm1pbWUuZGVmaW5lKFxuICB7XG4gICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCc6IFsnZm9ybScsICd1cmxlbmNvZGVkJywgJ2Zvcm0tZGF0YSddXG4gIH0sXG4gIHRydWVcbik7XG5cbi8qKlxuICogUHJvdG9jb2wgbWFwLlxuICovXG5cbmV4cG9ydHMucHJvdG9jb2xzID0ge1xuICAnaHR0cDonOiBodHRwLFxuICAnaHR0cHM6JzogaHR0cHMsXG4gICdodHRwMjonOiBodHRwMlxufTtcblxuLyoqXG4gKiBEZWZhdWx0IHNlcmlhbGl6YXRpb24gbWFwLlxuICpcbiAqICAgICBzdXBlcmFnZW50LnNlcmlhbGl6ZVsnYXBwbGljYXRpb24veG1sJ10gPSBmdW5jdGlvbihvYmope1xuICogICAgICAgcmV0dXJuICdnZW5lcmF0ZWQgeG1sIGhlcmUnO1xuICogICAgIH07XG4gKlxuICovXG5cbmV4cG9ydHMuc2VyaWFsaXplID0ge1xuICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJzogcXMuc3RyaW5naWZ5LFxuICAnYXBwbGljYXRpb24vanNvbic6IHNhZmVTdHJpbmdpZnlcbn07XG5cbi8qKlxuICogRGVmYXVsdCBwYXJzZXJzLlxuICpcbiAqICAgICBzdXBlcmFnZW50LnBhcnNlWydhcHBsaWNhdGlvbi94bWwnXSA9IGZ1bmN0aW9uKHJlcywgZm4pe1xuICogICAgICAgZm4obnVsbCwgcmVzKTtcbiAqICAgICB9O1xuICpcbiAqL1xuXG5leHBvcnRzLnBhcnNlID0gcmVxdWlyZSgnLi9wYXJzZXJzJyk7XG5cbi8qKlxuICogRGVmYXVsdCBidWZmZXJpbmcgbWFwLiBDYW4gYmUgdXNlZCB0byBzZXQgY2VydGFpblxuICogcmVzcG9uc2UgdHlwZXMgdG8gYnVmZmVyL25vdCBidWZmZXIuXG4gKlxuICogICAgIHN1cGVyYWdlbnQuYnVmZmVyWydhcHBsaWNhdGlvbi94bWwnXSA9IHRydWU7XG4gKi9cbmV4cG9ydHMuYnVmZmVyID0ge307XG5cbi8qKlxuICogSW5pdGlhbGl6ZSBpbnRlcm5hbCBoZWFkZXIgdHJhY2tpbmcgcHJvcGVydGllcyBvbiBhIHJlcXVlc3QgaW5zdGFuY2UuXG4gKlxuICogQHBhcmFtIHtPYmplY3R9IHJlcSB0aGUgaW5zdGFuY2VcbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5mdW5jdGlvbiBfaW5pdEhlYWRlcnMocmVxdWVzdF8pIHtcbiAgcmVxdWVzdF8uX2hlYWRlciA9IHtcbiAgICAvLyBjb2VyY2VzIGhlYWRlciBuYW1lcyB0byBsb3dlcmNhc2VcbiAgfTtcbiAgcmVxdWVzdF8uaGVhZGVyID0ge1xuICAgIC8vIHByZXNlcnZlcyBoZWFkZXIgbmFtZSBjYXNlXG4gIH07XG59XG5cbi8qKlxuICogSW5pdGlhbGl6ZSBhIG5ldyBgUmVxdWVzdGAgd2l0aCB0aGUgZ2l2ZW4gYG1ldGhvZGAgYW5kIGB1cmxgLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBtZXRob2RcbiAqIEBwYXJhbSB7U3RyaW5nfE9iamVjdH0gdXJsXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIFJlcXVlc3QobWV0aG9kLCB1cmwpIHtcbiAgU3RyZWFtLmNhbGwodGhpcyk7XG4gIGlmICh0eXBlb2YgdXJsICE9PSAnc3RyaW5nJykgdXJsID0gZm9ybWF0KHVybCk7XG4gIHRoaXMuX2VuYWJsZUh0dHAyID0gQm9vbGVhbihwcm9jZXNzLmVudi5IVFRQMl9URVNUKTsgLy8gaW50ZXJuYWwgb25seVxuICB0aGlzLl9hZ2VudCA9IGZhbHNlO1xuICB0aGlzLl9mb3JtRGF0YSA9IG51bGw7XG4gIHRoaXMubWV0aG9kID0gbWV0aG9kO1xuICB0aGlzLnVybCA9IHVybDtcbiAgX2luaXRIZWFkZXJzKHRoaXMpO1xuICB0aGlzLndyaXRhYmxlID0gdHJ1ZTtcbiAgdGhpcy5fcmVkaXJlY3RzID0gMDtcbiAgdGhpcy5yZWRpcmVjdHMobWV0aG9kID09PSAnSEVBRCcgPyAwIDogNSk7XG4gIHRoaXMuY29va2llcyA9ICcnO1xuICB0aGlzLnFzID0ge307XG4gIHRoaXMuX3F1ZXJ5ID0gW107XG4gIHRoaXMucXNSYXcgPSB0aGlzLl9xdWVyeTsgLy8gVW51c2VkLCBmb3IgYmFja3dhcmRzIGNvbXBhdGliaWxpdHkgb25seVxuICB0aGlzLl9yZWRpcmVjdExpc3QgPSBbXTtcbiAgdGhpcy5fc3RyZWFtUmVxdWVzdCA9IGZhbHNlO1xuICB0aGlzLl9sb29rdXAgPSB1bmRlZmluZWQ7XG4gIHRoaXMub25jZSgnZW5kJywgdGhpcy5jbGVhclRpbWVvdXQuYmluZCh0aGlzKSk7XG59XG5cbi8qKlxuICogSW5oZXJpdCBmcm9tIGBTdHJlYW1gICh3aGljaCBpbmhlcml0cyBmcm9tIGBFdmVudEVtaXR0ZXJgKS5cbiAqIE1peGluIGBSZXF1ZXN0QmFzZWAuXG4gKi9cbnV0aWwuaW5oZXJpdHMoUmVxdWVzdCwgU3RyZWFtKTtcblxubWl4aW4oUmVxdWVzdC5wcm90b3R5cGUsIFJlcXVlc3RCYXNlLnByb3RvdHlwZSk7XG5cbi8qKlxuICogRW5hYmxlIG9yIERpc2FibGUgaHR0cDIuXG4gKlxuICogRW5hYmxlIGh0dHAyLlxuICpcbiAqIGBgYCBqc1xuICogcmVxdWVzdC5nZXQoJ2h0dHA6Ly9sb2NhbGhvc3QvJylcbiAqICAgLmh0dHAyKClcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogcmVxdWVzdC5nZXQoJ2h0dHA6Ly9sb2NhbGhvc3QvJylcbiAqICAgLmh0dHAyKHRydWUpXG4gKiAgIC5lbmQoY2FsbGJhY2spO1xuICogYGBgXG4gKlxuICogRGlzYWJsZSBodHRwMi5cbiAqXG4gKiBgYGAganNcbiAqIHJlcXVlc3QgPSByZXF1ZXN0Lmh0dHAyKCk7XG4gKiByZXF1ZXN0LmdldCgnaHR0cDovL2xvY2FsaG9zdC8nKVxuICogICAuaHR0cDIoZmFsc2UpXG4gKiAgIC5lbmQoY2FsbGJhY2spO1xuICogYGBgXG4gKlxuICogQHBhcmFtIHtCb29sZWFufSBlbmFibGVcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5odHRwMiA9IGZ1bmN0aW9uIChib29sKSB7XG4gIGlmIChleHBvcnRzLnByb3RvY29sc1snaHR0cDI6J10gPT09IHVuZGVmaW5lZCkge1xuICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICdzdXBlcmFnZW50OiB0aGlzIHZlcnNpb24gb2YgTm9kZS5qcyBkb2VzIG5vdCBzdXBwb3J0IGh0dHAyJ1xuICAgICk7XG4gIH1cblxuICB0aGlzLl9lbmFibGVIdHRwMiA9IGJvb2wgPT09IHVuZGVmaW5lZCA/IHRydWUgOiBib29sO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogUXVldWUgdGhlIGdpdmVuIGBmaWxlYCBhcyBhbiBhdHRhY2htZW50IHRvIHRoZSBzcGVjaWZpZWQgYGZpZWxkYCxcbiAqIHdpdGggb3B0aW9uYWwgYG9wdGlvbnNgIChvciBmaWxlbmFtZSkuXG4gKlxuICogYGBgIGpzXG4gKiByZXF1ZXN0LnBvc3QoJ2h0dHA6Ly9sb2NhbGhvc3QvdXBsb2FkJylcbiAqICAgLmF0dGFjaCgnZmllbGQnLCBCdWZmZXIuZnJvbSgnPGI+SGVsbG8gd29ybGQ8L2I+JyksICdoZWxsby5odG1sJylcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKiBgYGBcbiAqXG4gKiBBIGZpbGVuYW1lIG1heSBhbHNvIGJlIHVzZWQ6XG4gKlxuICogYGBgIGpzXG4gKiByZXF1ZXN0LnBvc3QoJ2h0dHA6Ly9sb2NhbGhvc3QvdXBsb2FkJylcbiAqICAgLmF0dGFjaCgnZmlsZXMnLCAnaW1hZ2UuanBnJylcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKiBgYGBcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gZmllbGRcbiAqIEBwYXJhbSB7U3RyaW5nfGZzLlJlYWRTdHJlYW18QnVmZmVyfSBmaWxlXG4gKiBAcGFyYW0ge1N0cmluZ3xPYmplY3R9IG9wdGlvbnNcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5hdHRhY2ggPSBmdW5jdGlvbiAoZmllbGQsIGZpbGUsIG9wdGlvbnMpIHtcbiAgaWYgKGZpbGUpIHtcbiAgICBpZiAodGhpcy5fZGF0YSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwic3VwZXJhZ2VudCBjYW4ndCBtaXggLnNlbmQoKSBhbmQgLmF0dGFjaCgpXCIpO1xuICAgIH1cblxuICAgIGxldCBvID0gb3B0aW9ucyB8fCB7fTtcbiAgICBpZiAodHlwZW9mIG9wdGlvbnMgPT09ICdzdHJpbmcnKSB7XG4gICAgICBvID0geyBmaWxlbmFtZTogb3B0aW9ucyB9O1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgZmlsZSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIGlmICghby5maWxlbmFtZSkgby5maWxlbmFtZSA9IGZpbGU7XG4gICAgICBkZWJ1ZygnY3JlYXRpbmcgYGZzLlJlYWRTdHJlYW1gIGluc3RhbmNlIGZvciBmaWxlOiAlcycsIGZpbGUpO1xuICAgICAgZmlsZSA9IGZzLmNyZWF0ZVJlYWRTdHJlYW0oZmlsZSk7XG4gICAgICBmaWxlLm9uKCdlcnJvcicsIChlcnJvcikgPT4ge1xuICAgICAgICBjb25zdCBmb3JtRGF0YSA9IHRoaXMuX2dldEZvcm1EYXRhKCk7XG4gICAgICAgIGZvcm1EYXRhLmVtaXQoJ2Vycm9yJywgZXJyb3IpO1xuICAgICAgfSk7XG4gICAgfSBlbHNlIGlmICghby5maWxlbmFtZSAmJiBmaWxlLnBhdGgpIHtcbiAgICAgIG8uZmlsZW5hbWUgPSBmaWxlLnBhdGg7XG4gICAgfVxuXG4gICAgdGhpcy5fZ2V0Rm9ybURhdGEoKS5hcHBlbmQoZmllbGQsIGZpbGUsIG8pO1xuICB9XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5fZ2V0Rm9ybURhdGEgPSBmdW5jdGlvbiAoKSB7XG4gIGlmICghdGhpcy5fZm9ybURhdGEpIHtcbiAgICB0aGlzLl9mb3JtRGF0YSA9IG5ldyBGb3JtRGF0YSgpO1xuICAgIHRoaXMuX2Zvcm1EYXRhLm9uKCdlcnJvcicsIChlcnJvcikgPT4ge1xuICAgICAgZGVidWcoJ0Zvcm1EYXRhIGVycm9yJywgZXJyb3IpO1xuICAgICAgaWYgKHRoaXMuY2FsbGVkKSB7XG4gICAgICAgIC8vIFRoZSByZXF1ZXN0IGhhcyBhbHJlYWR5IGZpbmlzaGVkIGFuZCB0aGUgY2FsbGJhY2sgd2FzIGNhbGxlZC5cbiAgICAgICAgLy8gU2lsZW50bHkgaWdub3JlIHRoZSBlcnJvci5cbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICB0aGlzLmNhbGxiYWNrKGVycm9yKTtcbiAgICAgIHRoaXMuYWJvcnQoKTtcbiAgICB9KTtcbiAgfVxuXG4gIHJldHVybiB0aGlzLl9mb3JtRGF0YTtcbn07XG5cbi8qKlxuICogR2V0cy9zZXRzIHRoZSBgQWdlbnRgIHRvIHVzZSBmb3IgdGhpcyBIVFRQIHJlcXVlc3QuIFRoZSBkZWZhdWx0IChpZiB0aGlzXG4gKiBmdW5jdGlvbiBpcyBub3QgY2FsbGVkKSBpcyB0byBvcHQgb3V0IG9mIGNvbm5lY3Rpb24gcG9vbGluZyAoYGFnZW50OiBmYWxzZWApLlxuICpcbiAqIEBwYXJhbSB7aHR0cC5BZ2VudH0gYWdlbnRcbiAqIEByZXR1cm4ge2h0dHAuQWdlbnR9XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmFnZW50ID0gZnVuY3Rpb24gKGFnZW50KSB7XG4gIGlmIChhcmd1bWVudHMubGVuZ3RoID09PSAwKSByZXR1cm4gdGhpcy5fYWdlbnQ7XG4gIHRoaXMuX2FnZW50ID0gYWdlbnQ7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBHZXRzL3NldHMgdGhlIGBsb29rdXBgIGZ1bmN0aW9uIHRvIHVzZSBjdXN0b20gRE5TIHJlc29sdmVyLlxuICpcbiAqIEBwYXJhbSB7RnVuY3Rpb259IGxvb2t1cFxuICogQHJldHVybiB7RnVuY3Rpb259XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmxvb2t1cCA9IGZ1bmN0aW9uIChsb29rdXApIHtcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPT09IDApIHJldHVybiB0aGlzLl9sb29rdXA7XG4gIHRoaXMuX2xvb2t1cCA9IGxvb2t1cDtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNldCBfQ29udGVudC1UeXBlXyByZXNwb25zZSBoZWFkZXIgcGFzc2VkIHRocm91Z2ggYG1pbWUuZ2V0VHlwZSgpYC5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgICAgIHJlcXVlc3QucG9zdCgnLycpXG4gKiAgICAgICAgLnR5cGUoJ3htbCcpXG4gKiAgICAgICAgLnNlbmQoeG1sc3RyaW5nKVxuICogICAgICAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqICAgICAgcmVxdWVzdC5wb3N0KCcvJylcbiAqICAgICAgICAudHlwZSgnanNvbicpXG4gKiAgICAgICAgLnNlbmQoanNvbnN0cmluZylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiAgICAgIHJlcXVlc3QucG9zdCgnLycpXG4gKiAgICAgICAgLnR5cGUoJ2FwcGxpY2F0aW9uL2pzb24nKVxuICogICAgICAgIC5zZW5kKGpzb25zdHJpbmcpXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHR5cGVcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS50eXBlID0gZnVuY3Rpb24gKHR5cGUpIHtcbiAgcmV0dXJuIHRoaXMuc2V0KFxuICAgICdDb250ZW50LVR5cGUnLFxuICAgIHR5cGUuaW5jbHVkZXMoJy8nKSA/IHR5cGUgOiBtaW1lLmdldFR5cGUodHlwZSlcbiAgKTtcbn07XG5cbi8qKlxuICogU2V0IF9BY2NlcHRfIHJlc3BvbnNlIGhlYWRlciBwYXNzZWQgdGhyb3VnaCBgbWltZS5nZXRUeXBlKClgLlxuICpcbiAqIEV4YW1wbGVzOlxuICpcbiAqICAgICAgc3VwZXJhZ2VudC50eXBlcy5qc29uID0gJ2FwcGxpY2F0aW9uL2pzb24nO1xuICpcbiAqICAgICAgcmVxdWVzdC5nZXQoJy9hZ2VudCcpXG4gKiAgICAgICAgLmFjY2VwdCgnanNvbicpXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogICAgICByZXF1ZXN0LmdldCgnL2FnZW50JylcbiAqICAgICAgICAuYWNjZXB0KCdhcHBsaWNhdGlvbi9qc29uJylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gYWNjZXB0XG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuYWNjZXB0ID0gZnVuY3Rpb24gKHR5cGUpIHtcbiAgcmV0dXJuIHRoaXMuc2V0KCdBY2NlcHQnLCB0eXBlLmluY2x1ZGVzKCcvJykgPyB0eXBlIDogbWltZS5nZXRUeXBlKHR5cGUpKTtcbn07XG5cbi8qKlxuICogQWRkIHF1ZXJ5LXN0cmluZyBgdmFsYC5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgIHJlcXVlc3QuZ2V0KCcvc2hvZXMnKVxuICogICAgIC5xdWVyeSgnc2l6ZT0xMCcpXG4gKiAgICAgLnF1ZXJ5KHsgY29sb3I6ICdibHVlJyB9KVxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fFN0cmluZ30gdmFsXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUucXVlcnkgPSBmdW5jdGlvbiAodmFsdWUpIHtcbiAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ3N0cmluZycpIHtcbiAgICB0aGlzLl9xdWVyeS5wdXNoKHZhbHVlKTtcbiAgfSBlbHNlIHtcbiAgICBPYmplY3QuYXNzaWduKHRoaXMucXMsIHZhbHVlKTtcbiAgfVxuXG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBXcml0ZSByYXcgYGRhdGFgIC8gYGVuY29kaW5nYCB0byB0aGUgc29ja2V0LlxuICpcbiAqIEBwYXJhbSB7QnVmZmVyfFN0cmluZ30gZGF0YVxuICogQHBhcmFtIHtTdHJpbmd9IGVuY29kaW5nXG4gKiBAcmV0dXJuIHtCb29sZWFufVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS53cml0ZSA9IGZ1bmN0aW9uIChkYXRhLCBlbmNvZGluZykge1xuICBjb25zdCByZXF1ZXN0XyA9IHRoaXMucmVxdWVzdCgpO1xuICBpZiAoIXRoaXMuX3N0cmVhbVJlcXVlc3QpIHtcbiAgICB0aGlzLl9zdHJlYW1SZXF1ZXN0ID0gdHJ1ZTtcbiAgfVxuXG4gIHJldHVybiByZXF1ZXN0Xy53cml0ZShkYXRhLCBlbmNvZGluZyk7XG59O1xuXG4vKipcbiAqIFBpcGUgdGhlIHJlcXVlc3QgYm9keSB0byBgc3RyZWFtYC5cbiAqXG4gKiBAcGFyYW0ge1N0cmVhbX0gc3RyZWFtXG4gKiBAcGFyYW0ge09iamVjdH0gb3B0aW9uc1xuICogQHJldHVybiB7U3RyZWFtfVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5waXBlID0gZnVuY3Rpb24gKHN0cmVhbSwgb3B0aW9ucykge1xuICB0aGlzLnBpcGVkID0gdHJ1ZTsgLy8gSEFDSy4uLlxuICB0aGlzLmJ1ZmZlcihmYWxzZSk7XG4gIHRoaXMuZW5kKCk7XG4gIHJldHVybiB0aGlzLl9waXBlQ29udGludWUoc3RyZWFtLCBvcHRpb25zKTtcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLl9waXBlQ29udGludWUgPSBmdW5jdGlvbiAoc3RyZWFtLCBvcHRpb25zKSB7XG4gIHRoaXMucmVxLm9uY2UoJ3Jlc3BvbnNlJywgKHJlcykgPT4ge1xuICAgIC8vIHJlZGlyZWN0XG4gICAgaWYgKFxuICAgICAgaXNSZWRpcmVjdChyZXMuc3RhdHVzQ29kZSkgJiZcbiAgICAgIHRoaXMuX3JlZGlyZWN0cysrICE9PSB0aGlzLl9tYXhSZWRpcmVjdHNcbiAgICApIHtcbiAgICAgIHJldHVybiB0aGlzLl9yZWRpcmVjdChyZXMpID09PSB0aGlzXG4gICAgICAgID8gdGhpcy5fcGlwZUNvbnRpbnVlKHN0cmVhbSwgb3B0aW9ucylcbiAgICAgICAgOiB1bmRlZmluZWQ7XG4gICAgfVxuXG4gICAgdGhpcy5yZXMgPSByZXM7XG4gICAgdGhpcy5fZW1pdFJlc3BvbnNlKCk7XG4gICAgaWYgKHRoaXMuX2Fib3J0ZWQpIHJldHVybjtcblxuICAgIGlmICh0aGlzLl9zaG91bGRVbnppcChyZXMpKSB7XG4gICAgICBjb25zdCB1bnppcE9iamVjdCA9IHpsaWIuY3JlYXRlVW56aXAoKTtcbiAgICAgIHVuemlwT2JqZWN0Lm9uKCdlcnJvcicsIChlcnJvcikgPT4ge1xuICAgICAgICBpZiAoZXJyb3IgJiYgZXJyb3IuY29kZSA9PT0gJ1pfQlVGX0VSUk9SJykge1xuICAgICAgICAgIC8vIHVuZXhwZWN0ZWQgZW5kIG9mIGZpbGUgaXMgaWdub3JlZCBieSBicm93c2VycyBhbmQgY3VybFxuICAgICAgICAgIHN0cmVhbS5lbWl0KCdlbmQnKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBzdHJlYW0uZW1pdCgnZXJyb3InLCBlcnJvcik7XG4gICAgICB9KTtcbiAgICAgIHJlcy5waXBlKHVuemlwT2JqZWN0KS5waXBlKHN0cmVhbSwgb3B0aW9ucyk7XG4gICAgICAvLyBkb24ndCBlbWl0ICdlbmQnIHVudGlsIHVuemlwT2JqZWN0IGhhcyBjb21wbGV0ZWQgd3JpdGluZyBhbGwgaXRzIGRhdGEuXG4gICAgICB1bnppcE9iamVjdC5vbmNlKCdlbmQnLCAoKSA9PiB0aGlzLmVtaXQoJ2VuZCcpKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzLnBpcGUoc3RyZWFtLCBvcHRpb25zKTtcbiAgICAgIHJlcy5vbmNlKCdlbmQnLCAoKSA9PiB0aGlzLmVtaXQoJ2VuZCcpKTtcbiAgICB9XG4gIH0pO1xuICByZXR1cm4gc3RyZWFtO1xufTtcblxuLyoqXG4gKiBFbmFibGUgLyBkaXNhYmxlIGJ1ZmZlcmluZy5cbiAqXG4gKiBAcmV0dXJuIHtCb29sZWFufSBbdmFsXVxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmJ1ZmZlciA9IGZ1bmN0aW9uICh2YWx1ZSkge1xuICB0aGlzLl9idWZmZXIgPSB2YWx1ZSAhPT0gZmFsc2U7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBSZWRpcmVjdCB0byBgdXJsXG4gKlxuICogQHBhcmFtIHtJbmNvbWluZ01lc3NhZ2V9IHJlc1xuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5fcmVkaXJlY3QgPSBmdW5jdGlvbiAocmVzKSB7XG4gIGxldCB1cmwgPSByZXMuaGVhZGVycy5sb2NhdGlvbjtcbiAgaWYgKCF1cmwpIHtcbiAgICByZXR1cm4gdGhpcy5jYWxsYmFjayhuZXcgRXJyb3IoJ05vIGxvY2F0aW9uIGhlYWRlciBmb3IgcmVkaXJlY3QnKSwgcmVzKTtcbiAgfVxuXG4gIGRlYnVnKCdyZWRpcmVjdCAlcyAtPiAlcycsIHRoaXMudXJsLCB1cmwpO1xuXG4gIC8vIGxvY2F0aW9uXG4gIHVybCA9IHJlc29sdmUodGhpcy51cmwsIHVybCk7XG5cbiAgLy8gZW5zdXJlIHRoZSByZXNwb25zZSBpcyBiZWluZyBjb25zdW1lZFxuICAvLyB0aGlzIGlzIHJlcXVpcmVkIGZvciBOb2RlIHYwLjEwK1xuICByZXMucmVzdW1lKCk7XG5cbiAgbGV0IGhlYWRlcnMgPSB0aGlzLnJlcS5nZXRIZWFkZXJzID8gdGhpcy5yZXEuZ2V0SGVhZGVycygpIDogdGhpcy5yZXEuX2hlYWRlcnM7XG5cbiAgY29uc3QgY2hhbmdlc09yaWdpbiA9IHBhcnNlKHVybCkuaG9zdCAhPT0gcGFyc2UodGhpcy51cmwpLmhvc3Q7XG5cbiAgLy8gaW1wbGVtZW50YXRpb24gb2YgMzAyIGZvbGxvd2luZyBkZWZhY3RvIHN0YW5kYXJkXG4gIGlmIChyZXMuc3RhdHVzQ29kZSA9PT0gMzAxIHx8IHJlcy5zdGF0dXNDb2RlID09PSAzMDIpIHtcbiAgICAvLyBzdHJpcCBDb250ZW50LSogcmVsYXRlZCBmaWVsZHNcbiAgICAvLyBpbiBjYXNlIG9mIFBPU1QgZXRjXG4gICAgaGVhZGVycyA9IHV0aWxzLmNsZWFuSGVhZGVyKGhlYWRlcnMsIGNoYW5nZXNPcmlnaW4pO1xuXG4gICAgLy8gZm9yY2UgR0VUXG4gICAgdGhpcy5tZXRob2QgPSB0aGlzLm1ldGhvZCA9PT0gJ0hFQUQnID8gJ0hFQUQnIDogJ0dFVCc7XG5cbiAgICAvLyBjbGVhciBkYXRhXG4gICAgdGhpcy5fZGF0YSA9IG51bGw7XG4gIH1cblxuICAvLyAzMDMgaXMgYWx3YXlzIEdFVFxuICBpZiAocmVzLnN0YXR1c0NvZGUgPT09IDMwMykge1xuICAgIC8vIHN0cmlwIENvbnRlbnQtKiByZWxhdGVkIGZpZWxkc1xuICAgIC8vIGluIGNhc2Ugb2YgUE9TVCBldGNcbiAgICBoZWFkZXJzID0gdXRpbHMuY2xlYW5IZWFkZXIoaGVhZGVycywgY2hhbmdlc09yaWdpbik7XG5cbiAgICAvLyBmb3JjZSBtZXRob2RcbiAgICB0aGlzLm1ldGhvZCA9ICdHRVQnO1xuXG4gICAgLy8gY2xlYXIgZGF0YVxuICAgIHRoaXMuX2RhdGEgPSBudWxsO1xuICB9XG5cbiAgLy8gMzA3IHByZXNlcnZlcyBtZXRob2RcbiAgLy8gMzA4IHByZXNlcnZlcyBtZXRob2RcbiAgZGVsZXRlIGhlYWRlcnMuaG9zdDtcblxuICBkZWxldGUgdGhpcy5yZXE7XG4gIGRlbGV0ZSB0aGlzLl9mb3JtRGF0YTtcblxuICAvLyByZW1vdmUgYWxsIGFkZCBoZWFkZXIgZXhjZXB0IFVzZXItQWdlbnRcbiAgX2luaXRIZWFkZXJzKHRoaXMpO1xuXG4gIC8vIHJlZGlyZWN0XG4gIHRoaXMucmVzID0gcmVzO1xuICB0aGlzLl9lbmRDYWxsZWQgPSBmYWxzZTtcbiAgdGhpcy51cmwgPSB1cmw7XG4gIHRoaXMucXMgPSB7fTtcbiAgdGhpcy5fcXVlcnkubGVuZ3RoID0gMDtcbiAgdGhpcy5zZXQoaGVhZGVycyk7XG4gIHRoaXMuX2VtaXRSZWRpcmVjdCgpO1xuICB0aGlzLl9yZWRpcmVjdExpc3QucHVzaCh0aGlzLnVybCk7XG4gIHRoaXMuZW5kKHRoaXMuX2NhbGxiYWNrKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNldCBBdXRob3JpemF0aW9uIGZpZWxkIHZhbHVlIHdpdGggYHVzZXJgIGFuZCBgcGFzc2AuXG4gKlxuICogRXhhbXBsZXM6XG4gKlxuICogICAuYXV0aCgndG9iaScsICdsZWFybmJvb3N0JylcbiAqICAgLmF1dGgoJ3RvYmk6bGVhcm5ib29zdCcpXG4gKiAgIC5hdXRoKCd0b2JpJylcbiAqICAgLmF1dGgoYWNjZXNzVG9rZW4sIHsgdHlwZTogJ2JlYXJlcicgfSlcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gdXNlclxuICogQHBhcmFtIHtTdHJpbmd9IFtwYXNzXVxuICogQHBhcmFtIHtPYmplY3R9IFtvcHRpb25zXSBvcHRpb25zIHdpdGggYXV0aG9yaXphdGlvbiB0eXBlICdiYXNpYycgb3IgJ2JlYXJlcicgKCdiYXNpYycgaXMgZGVmYXVsdClcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5hdXRoID0gZnVuY3Rpb24gKHVzZXIsIHBhc3MsIG9wdGlvbnMpIHtcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPT09IDEpIHBhc3MgPSAnJztcbiAgaWYgKHR5cGVvZiBwYXNzID09PSAnb2JqZWN0JyAmJiBwYXNzICE9PSBudWxsKSB7XG4gICAgLy8gcGFzcyBpcyBvcHRpb25hbCBhbmQgY2FuIGJlIHJlcGxhY2VkIHdpdGggb3B0aW9uc1xuICAgIG9wdGlvbnMgPSBwYXNzO1xuICAgIHBhc3MgPSAnJztcbiAgfVxuXG4gIGlmICghb3B0aW9ucykge1xuICAgIG9wdGlvbnMgPSB7IHR5cGU6ICdiYXNpYycgfTtcbiAgfVxuXG4gIGNvbnN0IGVuY29kZXIgPSAoc3RyaW5nKSA9PiBCdWZmZXIuZnJvbShzdHJpbmcpLnRvU3RyaW5nKCdiYXNlNjQnKTtcblxuICByZXR1cm4gdGhpcy5fYXV0aCh1c2VyLCBwYXNzLCBvcHRpb25zLCBlbmNvZGVyKTtcbn07XG5cbi8qKlxuICogU2V0IHRoZSBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkgb3B0aW9uIGZvciBodHRwcyByZXF1ZXN0LlxuICpcbiAqIEBwYXJhbSB7QnVmZmVyIHwgQXJyYXl9IGNlcnRcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5jYSA9IGZ1bmN0aW9uIChjZXJ0KSB7XG4gIHRoaXMuX2NhID0gY2VydDtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNldCB0aGUgY2xpZW50IGNlcnRpZmljYXRlIGtleSBvcHRpb24gZm9yIGh0dHBzIHJlcXVlc3QuXG4gKlxuICogQHBhcmFtIHtCdWZmZXIgfCBTdHJpbmd9IGNlcnRcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5rZXkgPSBmdW5jdGlvbiAoY2VydCkge1xuICB0aGlzLl9rZXkgPSBjZXJ0O1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogU2V0IHRoZSBrZXksIGNlcnRpZmljYXRlLCBhbmQgQ0EgY2VydHMgb2YgdGhlIGNsaWVudCBpbiBQRlggb3IgUEtDUzEyIGZvcm1hdC5cbiAqXG4gKiBAcGFyYW0ge0J1ZmZlciB8IFN0cmluZ30gY2VydFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLnBmeCA9IGZ1bmN0aW9uIChjZXJ0KSB7XG4gIGlmICh0eXBlb2YgY2VydCA9PT0gJ29iamVjdCcgJiYgIUJ1ZmZlci5pc0J1ZmZlcihjZXJ0KSkge1xuICAgIHRoaXMuX3BmeCA9IGNlcnQucGZ4O1xuICAgIHRoaXMuX3Bhc3NwaHJhc2UgPSBjZXJ0LnBhc3NwaHJhc2U7XG4gIH0gZWxzZSB7XG4gICAgdGhpcy5fcGZ4ID0gY2VydDtcbiAgfVxuXG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBTZXQgdGhlIGNsaWVudCBjZXJ0aWZpY2F0ZSBvcHRpb24gZm9yIGh0dHBzIHJlcXVlc3QuXG4gKlxuICogQHBhcmFtIHtCdWZmZXIgfCBTdHJpbmd9IGNlcnRcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5jZXJ0ID0gZnVuY3Rpb24gKGNlcnQpIHtcbiAgdGhpcy5fY2VydCA9IGNlcnQ7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBEbyBub3QgcmVqZWN0IGV4cGlyZWQgb3IgaW52YWxpZCBUTFMgY2VydHMuXG4gKiBzZXRzIGByZWplY3RVbmF1dGhvcml6ZWQ9dHJ1ZWAuIEJlIHdhcm5lZCB0aGF0IHRoaXMgYWxsb3dzIE1JVE0gYXR0YWNrcy5cbiAqXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuZGlzYWJsZVRMU0NlcnRzID0gZnVuY3Rpb24gKCkge1xuICB0aGlzLl9kaXNhYmxlVExTQ2VydHMgPSB0cnVlO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogUmV0dXJuIGFuIGh0dHBbc10gcmVxdWVzdC5cbiAqXG4gKiBAcmV0dXJuIHtPdXRnb2luZ01lc3NhZ2V9XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgY29tcGxleGl0eVxuUmVxdWVzdC5wcm90b3R5cGUucmVxdWVzdCA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKHRoaXMucmVxKSByZXR1cm4gdGhpcy5yZXE7XG5cbiAgY29uc3Qgb3B0aW9ucyA9IHt9O1xuXG4gIHRyeSB7XG4gICAgY29uc3QgcXVlcnkgPSBxcy5zdHJpbmdpZnkodGhpcy5xcywge1xuICAgICAgaW5kaWNlczogZmFsc2UsXG4gICAgICBzdHJpY3ROdWxsSGFuZGxpbmc6IHRydWVcbiAgICB9KTtcbiAgICBpZiAocXVlcnkpIHtcbiAgICAgIHRoaXMucXMgPSB7fTtcbiAgICAgIHRoaXMuX3F1ZXJ5LnB1c2gocXVlcnkpO1xuICAgIH1cblxuICAgIHRoaXMuX2ZpbmFsaXplUXVlcnlTdHJpbmcoKTtcbiAgfSBjYXRjaCAoZXJyKSB7XG4gICAgcmV0dXJuIHRoaXMuZW1pdCgnZXJyb3InLCBlcnIpO1xuICB9XG5cbiAgbGV0IHsgdXJsIH0gPSB0aGlzO1xuICBjb25zdCByZXRyaWVzID0gdGhpcy5fcmV0cmllcztcblxuICAvLyBDYXB0dXJlIGJhY2t0aWNrcyBhcy1pcyBmcm9tIHRoZSBmaW5hbCBxdWVyeSBzdHJpbmcgYnVpbHQgYWJvdmUuXG4gIC8vIE5vdGU6IHRoaXMnbGwgb25seSBmaW5kIGJhY2t0aWNrcyBlbnRlcmVkIGluIHJlcS5xdWVyeShTdHJpbmcpXG4gIC8vIGNhbGxzLCBiZWNhdXNlIHFzLnN0cmluZ2lmeSB1bmNvbmRpdGlvbmFsbHkgZW5jb2RlcyBiYWNrdGlja3MuXG4gIGxldCBxdWVyeVN0cmluZ0JhY2t0aWNrcztcbiAgaWYgKHVybC5pbmNsdWRlcygnYCcpKSB7XG4gICAgY29uc3QgcXVlcnlTdGFydEluZGV4ID0gdXJsLmluZGV4T2YoJz8nKTtcblxuICAgIGlmIChxdWVyeVN0YXJ0SW5kZXggIT09IC0xKSB7XG4gICAgICBjb25zdCBxdWVyeVN0cmluZyA9IHVybC5zbGljZShxdWVyeVN0YXJ0SW5kZXggKyAxKTtcbiAgICAgIHF1ZXJ5U3RyaW5nQmFja3RpY2tzID0gcXVlcnlTdHJpbmcubWF0Y2goL2B8JTYwL2cpO1xuICAgIH1cbiAgfVxuXG4gIC8vIGRlZmF1bHQgdG8gaHR0cDovL1xuICBpZiAodXJsLmluZGV4T2YoJ2h0dHAnKSAhPT0gMCkgdXJsID0gYGh0dHA6Ly8ke3VybH1gO1xuICB1cmwgPSBwYXJzZSh1cmwpO1xuXG4gIC8vIFNlZSBodHRwczovL2dpdGh1Yi5jb20vbGFkanMvc3VwZXJhZ2VudC9pc3N1ZXMvMTM2N1xuICBpZiAocXVlcnlTdHJpbmdCYWNrdGlja3MpIHtcbiAgICBsZXQgaSA9IDA7XG4gICAgdXJsLnF1ZXJ5ID0gdXJsLnF1ZXJ5LnJlcGxhY2UoLyU2MC9nLCAoKSA9PiBxdWVyeVN0cmluZ0JhY2t0aWNrc1tpKytdKTtcbiAgICB1cmwuc2VhcmNoID0gYD8ke3VybC5xdWVyeX1gO1xuICAgIHVybC5wYXRoID0gdXJsLnBhdGhuYW1lICsgdXJsLnNlYXJjaDtcbiAgfVxuXG4gIC8vIHN1cHBvcnQgdW5peCBzb2NrZXRzXG4gIGlmICgvXmh0dHBzP1xcK3VuaXg6Ly50ZXN0KHVybC5wcm90b2NvbCkgPT09IHRydWUpIHtcbiAgICAvLyBnZXQgdGhlIHByb3RvY29sXG4gICAgdXJsLnByb3RvY29sID0gYCR7dXJsLnByb3RvY29sLnNwbGl0KCcrJylbMF19OmA7XG5cbiAgICAvLyBnZXQgdGhlIHNvY2tldCwgcGF0aFxuICAgIGNvbnN0IHVuaXhQYXJ0cyA9IHVybC5wYXRoLm1hdGNoKC9eKFteL10rKSguKykkLyk7XG4gICAgb3B0aW9ucy5zb2NrZXRQYXRoID0gdW5peFBhcnRzWzFdLnJlcGxhY2UoLyUyRi9nLCAnLycpO1xuICAgIHVybC5wYXRoID0gdW5peFBhcnRzWzJdO1xuICB9XG5cbiAgLy8gT3ZlcnJpZGUgSVAgYWRkcmVzcyBvZiBhIGhvc3RuYW1lXG4gIGlmICh0aGlzLl9jb25uZWN0T3ZlcnJpZGUpIHtcbiAgICBjb25zdCB7IGhvc3RuYW1lIH0gPSB1cmw7XG4gICAgY29uc3QgbWF0Y2ggPVxuICAgICAgaG9zdG5hbWUgaW4gdGhpcy5fY29ubmVjdE92ZXJyaWRlXG4gICAgICAgID8gdGhpcy5fY29ubmVjdE92ZXJyaWRlW2hvc3RuYW1lXVxuICAgICAgICA6IHRoaXMuX2Nvbm5lY3RPdmVycmlkZVsnKiddO1xuICAgIGlmIChtYXRjaCkge1xuICAgICAgLy8gYmFja3VwIHRoZSByZWFsIGhvc3RcbiAgICAgIGlmICghdGhpcy5faGVhZGVyLmhvc3QpIHtcbiAgICAgICAgdGhpcy5zZXQoJ2hvc3QnLCB1cmwuaG9zdCk7XG4gICAgICB9XG5cbiAgICAgIGxldCBuZXdIb3N0O1xuICAgICAgbGV0IG5ld1BvcnQ7XG5cbiAgICAgIGlmICh0eXBlb2YgbWF0Y2ggPT09ICdvYmplY3QnKSB7XG4gICAgICAgIG5ld0hvc3QgPSBtYXRjaC5ob3N0O1xuICAgICAgICBuZXdQb3J0ID0gbWF0Y2gucG9ydDtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIG5ld0hvc3QgPSBtYXRjaDtcbiAgICAgICAgbmV3UG9ydCA9IHVybC5wb3J0O1xuICAgICAgfVxuXG4gICAgICAvLyB3cmFwIFtpcHY2XVxuICAgICAgdXJsLmhvc3QgPSAvOi8udGVzdChuZXdIb3N0KSA/IGBbJHtuZXdIb3N0fV1gIDogbmV3SG9zdDtcbiAgICAgIGlmIChuZXdQb3J0KSB7XG4gICAgICAgIHVybC5ob3N0ICs9IGA6JHtuZXdQb3J0fWA7XG4gICAgICAgIHVybC5wb3J0ID0gbmV3UG9ydDtcbiAgICAgIH1cblxuICAgICAgdXJsLmhvc3RuYW1lID0gbmV3SG9zdDtcbiAgICB9XG4gIH1cblxuICAvLyBvcHRpb25zXG4gIG9wdGlvbnMubWV0aG9kID0gdGhpcy5tZXRob2Q7XG4gIG9wdGlvbnMucG9ydCA9IHVybC5wb3J0O1xuICBvcHRpb25zLnBhdGggPSB1cmwucGF0aDtcbiAgb3B0aW9ucy5ob3N0ID0gdXJsLmhvc3RuYW1lO1xuICBvcHRpb25zLmNhID0gdGhpcy5fY2E7XG4gIG9wdGlvbnMua2V5ID0gdGhpcy5fa2V5O1xuICBvcHRpb25zLnBmeCA9IHRoaXMuX3BmeDtcbiAgb3B0aW9ucy5jZXJ0ID0gdGhpcy5fY2VydDtcbiAgb3B0aW9ucy5wYXNzcGhyYXNlID0gdGhpcy5fcGFzc3BocmFzZTtcbiAgb3B0aW9ucy5hZ2VudCA9IHRoaXMuX2FnZW50O1xuICBvcHRpb25zLmxvb2t1cCA9IHRoaXMuX2xvb2t1cDtcbiAgb3B0aW9ucy5yZWplY3RVbmF1dGhvcml6ZWQgPVxuICAgIHR5cGVvZiB0aGlzLl9kaXNhYmxlVExTQ2VydHMgPT09ICdib29sZWFuJ1xuICAgICAgPyAhdGhpcy5fZGlzYWJsZVRMU0NlcnRzXG4gICAgICA6IHByb2Nlc3MuZW52Lk5PREVfVExTX1JFSkVDVF9VTkFVVEhPUklaRUQgIT09ICcwJztcblxuICAvLyBBbGxvd3MgcmVxdWVzdC5nZXQoJ2h0dHBzOi8vMS4yLjMuNC8nKS5zZXQoJ0hvc3QnLCAnZXhhbXBsZS5jb20nKVxuICBpZiAodGhpcy5faGVhZGVyLmhvc3QpIHtcbiAgICBvcHRpb25zLnNlcnZlcm5hbWUgPSB0aGlzLl9oZWFkZXIuaG9zdC5yZXBsYWNlKC86XFxkKyQvLCAnJyk7XG4gIH1cblxuICBpZiAoXG4gICAgdGhpcy5fdHJ1c3RMb2NhbGhvc3QgJiZcbiAgICAvXig/OmxvY2FsaG9zdHwxMjdcXC4wXFwuMFxcLlxcZCt8KDAqOikrOjAqMSkkLy50ZXN0KHVybC5ob3N0bmFtZSlcbiAgKSB7XG4gICAgb3B0aW9ucy5yZWplY3RVbmF1dGhvcml6ZWQgPSBmYWxzZTtcbiAgfVxuXG4gIC8vIGluaXRpYXRlIHJlcXVlc3RcbiAgY29uc3QgbW9kdWxlXyA9IHRoaXMuX2VuYWJsZUh0dHAyXG4gICAgPyBleHBvcnRzLnByb3RvY29sc1snaHR0cDI6J10uc2V0UHJvdG9jb2wodXJsLnByb3RvY29sKVxuICAgIDogZXhwb3J0cy5wcm90b2NvbHNbdXJsLnByb3RvY29sXTtcblxuICAvLyByZXF1ZXN0XG4gIHRoaXMucmVxID0gbW9kdWxlXy5yZXF1ZXN0KG9wdGlvbnMpO1xuICBjb25zdCB7IHJlcSB9ID0gdGhpcztcblxuICAvLyBzZXQgdGNwIG5vIGRlbGF5XG4gIHJlcS5zZXROb0RlbGF5KHRydWUpO1xuXG4gIGlmIChvcHRpb25zLm1ldGhvZCAhPT0gJ0hFQUQnKSB7XG4gICAgcmVxLnNldEhlYWRlcignQWNjZXB0LUVuY29kaW5nJywgJ2d6aXAsIGRlZmxhdGUnKTtcbiAgfVxuXG4gIHRoaXMucHJvdG9jb2wgPSB1cmwucHJvdG9jb2w7XG4gIHRoaXMuaG9zdCA9IHVybC5ob3N0O1xuXG4gIC8vIGV4cG9zZSBldmVudHNcbiAgcmVxLm9uY2UoJ2RyYWluJywgKCkgPT4ge1xuICAgIHRoaXMuZW1pdCgnZHJhaW4nKTtcbiAgfSk7XG5cbiAgcmVxLm9uKCdlcnJvcicsIChlcnJvcikgPT4ge1xuICAgIC8vIGZsYWcgYWJvcnRpb24gaGVyZSBmb3Igb3V0IHRpbWVvdXRzXG4gICAgLy8gYmVjYXVzZSBub2RlIHdpbGwgZW1pdCBhIGZhdXgtZXJyb3IgXCJzb2NrZXQgaGFuZyB1cFwiXG4gICAgLy8gd2hlbiByZXF1ZXN0IGlzIGFib3J0ZWQgYmVmb3JlIGEgY29ubmVjdGlvbiBpcyBtYWRlXG4gICAgaWYgKHRoaXMuX2Fib3J0ZWQpIHJldHVybjtcbiAgICAvLyBpZiBub3QgdGhlIHNhbWUsIHdlIGFyZSBpbiB0aGUgKipvbGQqKiAoY2FuY2VsbGVkKSByZXF1ZXN0LFxuICAgIC8vIHNvIG5lZWQgdG8gY29udGludWUgKHNhbWUgYXMgZm9yIGFib3ZlKVxuICAgIGlmICh0aGlzLl9yZXRyaWVzICE9PSByZXRyaWVzKSByZXR1cm47XG4gICAgLy8gaWYgd2UndmUgcmVjZWl2ZWQgYSByZXNwb25zZSB0aGVuIHdlIGRvbid0IHdhbnQgdG8gbGV0XG4gICAgLy8gYW4gZXJyb3IgaW4gdGhlIHJlcXVlc3QgYmxvdyB1cCB0aGUgcmVzcG9uc2VcbiAgICBpZiAodGhpcy5yZXNwb25zZSkgcmV0dXJuO1xuICAgIHRoaXMuY2FsbGJhY2soZXJyb3IpO1xuICB9KTtcblxuICAvLyBhdXRoXG4gIGlmICh1cmwuYXV0aCkge1xuICAgIGNvbnN0IGF1dGggPSB1cmwuYXV0aC5zcGxpdCgnOicpO1xuICAgIHRoaXMuYXV0aChhdXRoWzBdLCBhdXRoWzFdKTtcbiAgfVxuXG4gIGlmICh0aGlzLnVzZXJuYW1lICYmIHRoaXMucGFzc3dvcmQpIHtcbiAgICB0aGlzLmF1dGgodGhpcy51c2VybmFtZSwgdGhpcy5wYXNzd29yZCk7XG4gIH1cblxuICBmb3IgKGNvbnN0IGtleSBpbiB0aGlzLmhlYWRlcikge1xuICAgIGlmIChoYXNPd24odGhpcy5oZWFkZXIsIGtleSkpIHJlcS5zZXRIZWFkZXIoa2V5LCB0aGlzLmhlYWRlcltrZXldKTtcbiAgfVxuXG4gIC8vIGFkZCBjb29raWVzXG4gIGlmICh0aGlzLmNvb2tpZXMpIHtcbiAgICBpZiAoaGFzT3duKHRoaXMuX2hlYWRlciwgJ2Nvb2tpZScpKSB7XG4gICAgICAvLyBtZXJnZVxuICAgICAgY29uc3QgdGVtcG9yYXJ5SmFyID0gbmV3IENvb2tpZUphci5Db29raWVKYXIoKTtcbiAgICAgIHRlbXBvcmFyeUphci5zZXRDb29raWVzKHRoaXMuX2hlYWRlci5jb29raWUuc3BsaXQoJzsgJykpO1xuICAgICAgdGVtcG9yYXJ5SmFyLnNldENvb2tpZXModGhpcy5jb29raWVzLnNwbGl0KCc7ICcpKTtcbiAgICAgIHJlcS5zZXRIZWFkZXIoXG4gICAgICAgICdDb29raWUnLFxuICAgICAgICB0ZW1wb3JhcnlKYXIuZ2V0Q29va2llcyhDb29raWVKYXIuQ29va2llQWNjZXNzSW5mby5BbGwpLnRvVmFsdWVTdHJpbmcoKVxuICAgICAgKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVxLnNldEhlYWRlcignQ29va2llJywgdGhpcy5jb29raWVzKTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gcmVxO1xufTtcblxuLyoqXG4gKiBJbnZva2UgdGhlIGNhbGxiYWNrIHdpdGggYGVycmAgYW5kIGByZXNgXG4gKiBhbmQgaGFuZGxlIGFyaXR5IGNoZWNrLlxuICpcbiAqIEBwYXJhbSB7RXJyb3J9IGVyclxuICogQHBhcmFtIHtSZXNwb25zZX0gcmVzXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5jYWxsYmFjayA9IGZ1bmN0aW9uIChlcnJvciwgcmVzKSB7XG4gIGlmICh0aGlzLl9zaG91bGRSZXRyeShlcnJvciwgcmVzKSkge1xuICAgIHJldHVybiB0aGlzLl9yZXRyeSgpO1xuICB9XG5cbiAgLy8gQXZvaWQgdGhlIGVycm9yIHdoaWNoIGlzIGVtaXR0ZWQgZnJvbSAnc29ja2V0IGhhbmcgdXAnIHRvIGNhdXNlIHRoZSBmbiB1bmRlZmluZWQgZXJyb3Igb24gSlMgcnVudGltZS5cbiAgY29uc3QgZm4gPSB0aGlzLl9jYWxsYmFjayB8fCBub29wO1xuICB0aGlzLmNsZWFyVGltZW91dCgpO1xuICBpZiAodGhpcy5jYWxsZWQpIHJldHVybiBjb25zb2xlLndhcm4oJ3N1cGVyYWdlbnQ6IGRvdWJsZSBjYWxsYmFjayBidWcnKTtcbiAgdGhpcy5jYWxsZWQgPSB0cnVlO1xuXG4gIGlmICghZXJyb3IpIHtcbiAgICB0cnkge1xuICAgICAgaWYgKCF0aGlzLl9pc1Jlc3BvbnNlT0socmVzKSkge1xuICAgICAgICBsZXQgbWVzc2FnZSA9ICdVbnN1Y2Nlc3NmdWwgSFRUUCByZXNwb25zZSc7XG4gICAgICAgIGlmIChyZXMpIHtcbiAgICAgICAgICBtZXNzYWdlID0gaHR0cC5TVEFUVVNfQ09ERVNbcmVzLnN0YXR1c10gfHwgbWVzc2FnZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGVycm9yID0gbmV3IEVycm9yKG1lc3NhZ2UpO1xuICAgICAgICBlcnJvci5zdGF0dXMgPSByZXMgPyByZXMuc3RhdHVzIDogdW5kZWZpbmVkO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgZXJyb3IgPSBlcnI7XG4gICAgICBlcnJvci5zdGF0dXMgPSBlcnJvci5zdGF0dXMgfHwgKHJlcyA/IHJlcy5zdGF0dXMgOiB1bmRlZmluZWQpO1xuICAgIH1cbiAgfVxuXG4gIC8vIEl0J3MgaW1wb3J0YW50IHRoYXQgdGhlIGNhbGxiYWNrIGlzIGNhbGxlZCBvdXRzaWRlIHRyeS9jYXRjaFxuICAvLyB0byBhdm9pZCBkb3VibGUgY2FsbGJhY2tcbiAgaWYgKCFlcnJvcikge1xuICAgIHJldHVybiBmbihudWxsLCByZXMpO1xuICB9XG5cbiAgZXJyb3IucmVzcG9uc2UgPSByZXM7XG4gIGlmICh0aGlzLl9tYXhSZXRyaWVzKSBlcnJvci5yZXRyaWVzID0gdGhpcy5fcmV0cmllcyAtIDE7XG5cbiAgLy8gb25seSBlbWl0IGVycm9yIGV2ZW50IGlmIHRoZXJlIGlzIGEgbGlzdGVuZXJcbiAgLy8gb3RoZXJ3aXNlIHdlIGFzc3VtZSB0aGUgY2FsbGJhY2sgdG8gYC5lbmQoKWAgd2lsbCBnZXQgdGhlIGVycm9yXG4gIGlmIChlcnJvciAmJiB0aGlzLmxpc3RlbmVycygnZXJyb3InKS5sZW5ndGggPiAwKSB7XG4gICAgdGhpcy5lbWl0KCdlcnJvcicsIGVycm9yKTtcbiAgfVxuXG4gIGZuKGVycm9yLCByZXMpO1xufTtcblxuLyoqXG4gKiBDaGVjayBpZiBgb2JqYCBpcyBhIGhvc3Qgb2JqZWN0LFxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmogaG9zdCBvYmplY3RcbiAqIEByZXR1cm4ge0Jvb2xlYW59IGlzIGEgaG9zdCBvYmplY3RcbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5SZXF1ZXN0LnByb3RvdHlwZS5faXNIb3N0ID0gZnVuY3Rpb24gKG9iamVjdCkge1xuICByZXR1cm4gKFxuICAgIEJ1ZmZlci5pc0J1ZmZlcihvYmplY3QpIHx8XG4gICAgb2JqZWN0IGluc3RhbmNlb2YgU3RyZWFtIHx8XG4gICAgb2JqZWN0IGluc3RhbmNlb2YgRm9ybURhdGFcbiAgKTtcbn07XG5cbi8qKlxuICogSW5pdGlhdGUgcmVxdWVzdCwgaW52b2tpbmcgY2FsbGJhY2sgYGZuKGVyciwgcmVzKWBcbiAqIHdpdGggYW4gaW5zdGFuY2VvZiBgUmVzcG9uc2VgLlxuICpcbiAqIEBwYXJhbSB7RnVuY3Rpb259IGZuXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuX2VtaXRSZXNwb25zZSA9IGZ1bmN0aW9uIChib2R5LCBmaWxlcykge1xuICBjb25zdCByZXNwb25zZSA9IG5ldyBSZXNwb25zZSh0aGlzKTtcbiAgdGhpcy5yZXNwb25zZSA9IHJlc3BvbnNlO1xuICByZXNwb25zZS5yZWRpcmVjdHMgPSB0aGlzLl9yZWRpcmVjdExpc3Q7XG4gIGlmICh1bmRlZmluZWQgIT09IGJvZHkpIHtcbiAgICByZXNwb25zZS5ib2R5ID0gYm9keTtcbiAgfVxuXG4gIHJlc3BvbnNlLmZpbGVzID0gZmlsZXM7XG4gIGlmICh0aGlzLl9lbmRDYWxsZWQpIHtcbiAgICByZXNwb25zZS5waXBlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICBcImVuZCgpIGhhcyBhbHJlYWR5IGJlZW4gY2FsbGVkLCBzbyBpdCdzIHRvbyBsYXRlIHRvIHN0YXJ0IHBpcGluZ1wiXG4gICAgICApO1xuICAgIH07XG4gIH1cblxuICB0aGlzLmVtaXQoJ3Jlc3BvbnNlJywgcmVzcG9uc2UpO1xuICByZXR1cm4gcmVzcG9uc2U7XG59O1xuXG4vKipcbiAqIEVtaXQgYHJlZGlyZWN0YCBldmVudCwgcGFzc2luZyBhbiBpbnN0YW5jZW9mIGBSZXNwb25zZWAuXG4gKlxuICogQGFwaSBwcml2YXRlXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuX2VtaXRSZWRpcmVjdCA9IGZ1bmN0aW9uICgpIHtcbiAgY29uc3QgcmVzcG9uc2UgPSBuZXcgUmVzcG9uc2UodGhpcyk7XG4gIHJlc3BvbnNlLnJlZGlyZWN0cyA9IHRoaXMuX3JlZGlyZWN0TGlzdDtcbiAgdGhpcy5lbWl0KCdyZWRpcmVjdCcsIHJlc3BvbnNlKTtcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLmVuZCA9IGZ1bmN0aW9uIChmbikge1xuICB0aGlzLnJlcXVlc3QoKTtcbiAgZGVidWcoJyVzICVzJywgdGhpcy5tZXRob2QsIHRoaXMudXJsKTtcblxuICBpZiAodGhpcy5fZW5kQ2FsbGVkKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgJy5lbmQoKSB3YXMgY2FsbGVkIHR3aWNlLiBUaGlzIGlzIG5vdCBzdXBwb3J0ZWQgaW4gc3VwZXJhZ2VudCdcbiAgICApO1xuICB9XG5cbiAgdGhpcy5fZW5kQ2FsbGVkID0gdHJ1ZTtcblxuICAvLyBzdG9yZSBjYWxsYmFja1xuICB0aGlzLl9jYWxsYmFjayA9IGZuIHx8IG5vb3A7XG5cbiAgdGhpcy5fZW5kKCk7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5fZW5kID0gZnVuY3Rpb24gKCkge1xuICBpZiAodGhpcy5fYWJvcnRlZClcbiAgICByZXR1cm4gdGhpcy5jYWxsYmFjayhcbiAgICAgIG5ldyBFcnJvcignVGhlIHJlcXVlc3QgaGFzIGJlZW4gYWJvcnRlZCBldmVuIGJlZm9yZSAuZW5kKCkgd2FzIGNhbGxlZCcpXG4gICAgKTtcblxuICBsZXQgZGF0YSA9IHRoaXMuX2RhdGE7XG4gIGNvbnN0IHsgcmVxIH0gPSB0aGlzO1xuICBjb25zdCB7IG1ldGhvZCB9ID0gdGhpcztcblxuICB0aGlzLl9zZXRUaW1lb3V0cygpO1xuXG4gIC8vIGJvZHlcbiAgaWYgKG1ldGhvZCAhPT0gJ0hFQUQnICYmICFyZXEuX2hlYWRlclNlbnQpIHtcbiAgICAvLyBzZXJpYWxpemUgc3R1ZmZcbiAgICBpZiAodHlwZW9mIGRhdGEgIT09ICdzdHJpbmcnKSB7XG4gICAgICBsZXQgY29udGVudFR5cGUgPSByZXEuZ2V0SGVhZGVyKCdDb250ZW50LVR5cGUnKTtcbiAgICAgIC8vIFBhcnNlIG91dCBqdXN0IHRoZSBjb250ZW50IHR5cGUgZnJvbSB0aGUgaGVhZGVyIChpZ25vcmUgdGhlIGNoYXJzZXQpXG4gICAgICBpZiAoY29udGVudFR5cGUpIGNvbnRlbnRUeXBlID0gY29udGVudFR5cGUuc3BsaXQoJzsnKVswXTtcbiAgICAgIGxldCBzZXJpYWxpemUgPSB0aGlzLl9zZXJpYWxpemVyIHx8IGV4cG9ydHMuc2VyaWFsaXplW2NvbnRlbnRUeXBlXTtcbiAgICAgIGlmICghc2VyaWFsaXplICYmIGlzSlNPTihjb250ZW50VHlwZSkpIHtcbiAgICAgICAgc2VyaWFsaXplID0gZXhwb3J0cy5zZXJpYWxpemVbJ2FwcGxpY2F0aW9uL2pzb24nXTtcbiAgICAgIH1cblxuICAgICAgaWYgKHNlcmlhbGl6ZSkgZGF0YSA9IHNlcmlhbGl6ZShkYXRhKTtcbiAgICB9XG5cbiAgICAvLyBjb250ZW50LWxlbmd0aFxuICAgIGlmIChkYXRhICYmICFyZXEuZ2V0SGVhZGVyKCdDb250ZW50LUxlbmd0aCcpKSB7XG4gICAgICByZXEuc2V0SGVhZGVyKFxuICAgICAgICAnQ29udGVudC1MZW5ndGgnLFxuICAgICAgICBCdWZmZXIuaXNCdWZmZXIoZGF0YSkgPyBkYXRhLmxlbmd0aCA6IEJ1ZmZlci5ieXRlTGVuZ3RoKGRhdGEpXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIC8vIHJlc3BvbnNlXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBjb21wbGV4aXR5XG4gIHJlcS5vbmNlKCdyZXNwb25zZScsIChyZXMpID0+IHtcbiAgICBkZWJ1ZygnJXMgJXMgLT4gJXMnLCB0aGlzLm1ldGhvZCwgdGhpcy51cmwsIHJlcy5zdGF0dXNDb2RlKTtcblxuICAgIGlmICh0aGlzLl9yZXNwb25zZVRpbWVvdXRUaW1lcikge1xuICAgICAgY2xlYXJUaW1lb3V0KHRoaXMuX3Jlc3BvbnNlVGltZW91dFRpbWVyKTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5waXBlZCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IG1heCA9IHRoaXMuX21heFJlZGlyZWN0cztcbiAgICBjb25zdCBtaW1lID0gdXRpbHMudHlwZShyZXMuaGVhZGVyc1snY29udGVudC10eXBlJ10gfHwgJycpIHx8ICd0ZXh0L3BsYWluJztcbiAgICBsZXQgdHlwZSA9IG1pbWUuc3BsaXQoJy8nKVswXTtcbiAgICBpZiAodHlwZSkgdHlwZSA9IHR5cGUudG9Mb3dlckNhc2UoKS50cmltKCk7XG4gICAgY29uc3QgbXVsdGlwYXJ0ID0gdHlwZSA9PT0gJ211bHRpcGFydCc7XG4gICAgY29uc3QgcmVkaXJlY3QgPSBpc1JlZGlyZWN0KHJlcy5zdGF0dXNDb2RlKTtcbiAgICBjb25zdCByZXNwb25zZVR5cGUgPSB0aGlzLl9yZXNwb25zZVR5cGU7XG5cbiAgICB0aGlzLnJlcyA9IHJlcztcblxuICAgIC8vIHJlZGlyZWN0XG4gICAgaWYgKHJlZGlyZWN0ICYmIHRoaXMuX3JlZGlyZWN0cysrICE9PSBtYXgpIHtcbiAgICAgIHJldHVybiB0aGlzLl9yZWRpcmVjdChyZXMpO1xuICAgIH1cblxuICAgIGlmICh0aGlzLm1ldGhvZCA9PT0gJ0hFQUQnKSB7XG4gICAgICB0aGlzLmVtaXQoJ2VuZCcpO1xuICAgICAgdGhpcy5jYWxsYmFjayhudWxsLCB0aGlzLl9lbWl0UmVzcG9uc2UoKSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gemxpYiBzdXBwb3J0XG4gICAgaWYgKHRoaXMuX3Nob3VsZFVuemlwKHJlcykpIHtcbiAgICAgIHVuemlwKHJlcSwgcmVzKTtcbiAgICB9XG5cbiAgICBsZXQgYnVmZmVyID0gdGhpcy5fYnVmZmVyO1xuICAgIGlmIChidWZmZXIgPT09IHVuZGVmaW5lZCAmJiBtaW1lIGluIGV4cG9ydHMuYnVmZmVyKSB7XG4gICAgICBidWZmZXIgPSBCb29sZWFuKGV4cG9ydHMuYnVmZmVyW21pbWVdKTtcbiAgICB9XG5cbiAgICBsZXQgcGFyc2VyID0gdGhpcy5fcGFyc2VyO1xuICAgIGlmICh1bmRlZmluZWQgPT09IGJ1ZmZlciAmJiBwYXJzZXIpIHtcbiAgICAgIGNvbnNvbGUud2FybihcbiAgICAgICAgXCJBIGN1c3RvbSBzdXBlcmFnZW50IHBhcnNlciBoYXMgYmVlbiBzZXQsIGJ1dCBidWZmZXJpbmcgc3RyYXRlZ3kgZm9yIHRoZSBwYXJzZXIgaGFzbid0IGJlZW4gY29uZmlndXJlZC4gQ2FsbCBgcmVxLmJ1ZmZlcih0cnVlIG9yIGZhbHNlKWAgb3Igc2V0IGBzdXBlcmFnZW50LmJ1ZmZlclttaW1lXSA9IHRydWUgb3IgZmFsc2VgXCJcbiAgICAgICk7XG4gICAgICBidWZmZXIgPSB0cnVlO1xuICAgIH1cblxuICAgIGlmICghcGFyc2VyKSB7XG4gICAgICBpZiAocmVzcG9uc2VUeXBlKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2UuaW1hZ2U7IC8vIEl0J3MgYWN0dWFsbHkgYSBnZW5lcmljIEJ1ZmZlclxuICAgICAgICBidWZmZXIgPSB0cnVlO1xuICAgICAgfSBlbHNlIGlmIChtdWx0aXBhcnQpIHtcbiAgICAgICAgY29uc3QgZm9ybSA9IGZvcm1pZGFibGUuZm9ybWlkYWJsZSgpO1xuICAgICAgICBwYXJzZXIgPSBmb3JtLnBhcnNlLmJpbmQoZm9ybSk7XG4gICAgICAgIGJ1ZmZlciA9IHRydWU7XG4gICAgICB9IGVsc2UgaWYgKGlzQmluYXJ5KG1pbWUpKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2UuaW1hZ2U7XG4gICAgICAgIGJ1ZmZlciA9IHRydWU7IC8vIEZvciBiYWNrd2FyZHMtY29tcGF0aWJpbGl0eSBidWZmZXJpbmcgZGVmYXVsdCBpcyBhZC1ob2MgTUlNRS1kZXBlbmRlbnRcbiAgICAgIH0gZWxzZSBpZiAoZXhwb3J0cy5wYXJzZVttaW1lXSkge1xuICAgICAgICBwYXJzZXIgPSBleHBvcnRzLnBhcnNlW21pbWVdO1xuICAgICAgfSBlbHNlIGlmICh0eXBlID09PSAndGV4dCcpIHtcbiAgICAgICAgcGFyc2VyID0gZXhwb3J0cy5wYXJzZS50ZXh0O1xuICAgICAgICBidWZmZXIgPSBidWZmZXIgIT09IGZhbHNlO1xuICAgICAgICAvLyBldmVyeW9uZSB3YW50cyB0aGVpciBvd24gd2hpdGUtbGFiZWxlZCBqc29uXG4gICAgICB9IGVsc2UgaWYgKGlzSlNPTihtaW1lKSkge1xuICAgICAgICBwYXJzZXIgPSBleHBvcnRzLnBhcnNlWydhcHBsaWNhdGlvbi9qc29uJ107XG4gICAgICAgIGJ1ZmZlciA9IGJ1ZmZlciAhPT0gZmFsc2U7XG4gICAgICB9IGVsc2UgaWYgKGJ1ZmZlcikge1xuICAgICAgICBwYXJzZXIgPSBleHBvcnRzLnBhcnNlLnRleHQ7XG4gICAgICB9IGVsc2UgaWYgKHVuZGVmaW5lZCA9PT0gYnVmZmVyKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2UuaW1hZ2U7IC8vIEl0J3MgYWN0dWFsbHkgYSBnZW5lcmljIEJ1ZmZlclxuICAgICAgICBidWZmZXIgPSB0cnVlO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIGJ5IGRlZmF1bHQgb25seSBidWZmZXIgdGV4dC8qLCBqc29uIGFuZCBtZXNzZWQgdXAgdGhpbmcgZnJvbSBoZWxsXG4gICAgaWYgKCh1bmRlZmluZWQgPT09IGJ1ZmZlciAmJiBpc1RleHQobWltZSkpIHx8IGlzSlNPTihtaW1lKSkge1xuICAgICAgYnVmZmVyID0gdHJ1ZTtcbiAgICB9XG5cbiAgICB0aGlzLl9yZXNCdWZmZXJlZCA9IGJ1ZmZlcjtcbiAgICBsZXQgcGFyc2VySGFuZGxlc0VuZCA9IGZhbHNlO1xuICAgIGlmIChidWZmZXIpIHtcbiAgICAgIC8vIFByb3RlY3Rpb25hIGFnYWluc3QgemlwIGJvbWJzIGFuZCBvdGhlciBudWlzYW5jZVxuICAgICAgbGV0IHJlc3BvbnNlQnl0ZXNMZWZ0ID0gdGhpcy5fbWF4UmVzcG9uc2VTaXplIHx8IDIwMDAwMDAwMDtcbiAgICAgIHJlcy5vbignZGF0YScsIChidWYpID0+IHtcbiAgICAgICAgcmVzcG9uc2VCeXRlc0xlZnQgLT0gYnVmLmJ5dGVMZW5ndGggfHwgYnVmLmxlbmd0aCA+IDAgPyBidWYubGVuZ3RoIDogMDtcbiAgICAgICAgaWYgKHJlc3BvbnNlQnl0ZXNMZWZ0IDwgMCkge1xuICAgICAgICAgIC8vIFRoaXMgd2lsbCBwcm9wYWdhdGUgdGhyb3VnaCBlcnJvciBldmVudFxuICAgICAgICAgIGNvbnN0IGVycm9yID0gbmV3IEVycm9yKCdNYXhpbXVtIHJlc3BvbnNlIHNpemUgcmVhY2hlZCcpO1xuICAgICAgICAgIGVycm9yLmNvZGUgPSAnRVRPT0xBUkdFJztcbiAgICAgICAgICAvLyBQYXJzZXJzIGFyZW4ndCByZXF1aXJlZCB0byBvYnNlcnZlIGVycm9yIGV2ZW50LFxuICAgICAgICAgIC8vIHNvIHdvdWxkIGluY29ycmVjdGx5IHJlcG9ydCBzdWNjZXNzXG4gICAgICAgICAgcGFyc2VySGFuZGxlc0VuZCA9IGZhbHNlO1xuICAgICAgICAgIC8vIFdpbGwgbm90IGVtaXQgZXJyb3IgZXZlbnRcbiAgICAgICAgICByZXMuZGVzdHJveShlcnJvcik7XG4gICAgICAgICAgLy8gc28gd2UgZG8gY2FsbGJhY2sgbm93XG4gICAgICAgICAgdGhpcy5jYWxsYmFjayhlcnJvciwgbnVsbCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGlmIChwYXJzZXIpIHtcbiAgICAgIHRyeSB7XG4gICAgICAgIC8vIFVuYnVmZmVyZWQgcGFyc2VycyBhcmUgc3VwcG9zZWQgdG8gZW1pdCByZXNwb25zZSBlYXJseSxcbiAgICAgICAgLy8gd2hpY2ggaXMgd2VpcmQgQlRXLCBiZWNhdXNlIHJlc3BvbnNlLmJvZHkgd29uJ3QgYmUgdGhlcmUuXG4gICAgICAgIHBhcnNlckhhbmRsZXNFbmQgPSBidWZmZXI7XG5cbiAgICAgICAgcGFyc2VyKHJlcywgKGVycm9yLCBvYmplY3QsIGZpbGVzKSA9PiB7XG4gICAgICAgICAgaWYgKHRoaXMudGltZWRvdXQpIHtcbiAgICAgICAgICAgIC8vIFRpbWVvdXQgaGFzIGFscmVhZHkgaGFuZGxlZCBhbGwgY2FsbGJhY2tzXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gSW50ZW50aW9uYWwgKG5vbi10aW1lb3V0KSBhYm9ydCBpcyBzdXBwb3NlZCB0byBwcmVzZXJ2ZSBwYXJ0aWFsIHJlc3BvbnNlLFxuICAgICAgICAgIC8vIGV2ZW4gaWYgaXQgZG9lc24ndCBwYXJzZS5cbiAgICAgICAgICBpZiAoZXJyb3IgJiYgIXRoaXMuX2Fib3J0ZWQpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmNhbGxiYWNrKGVycm9yKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocGFyc2VySGFuZGxlc0VuZCkge1xuICAgICAgICAgICAgaWYgKG11bHRpcGFydCkge1xuICAgICAgICAgICAgICAvLyBmb3JtaWRhYmxlIHYzIGFsd2F5cyByZXR1cm5zIGFuIGFycmF5IHdpdGggdGhlIHZhbHVlIGluIGl0XG4gICAgICAgICAgICAgIC8vIHNvIHdlIG5lZWQgdG8gZmxhdHRlbiBpdFxuICAgICAgICAgICAgICBpZiAob2JqZWN0KSB7XG4gICAgICAgICAgICAgICAgZm9yIChjb25zdCBrZXkgaW4gb2JqZWN0KSB7XG4gICAgICAgICAgICAgICAgICBjb25zdCB2YWx1ZSA9IG9iamVjdFtrZXldO1xuICAgICAgICAgICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkodmFsdWUpICYmIHZhbHVlLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICAgICAgICAgICAgICBvYmplY3Rba2V5XSA9IHZhbHVlWzBdO1xuICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgb2JqZWN0W2tleV0gPSB2YWx1ZTtcbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICBpZiAoZmlsZXMpIHtcbiAgICAgICAgICAgICAgICBmb3IgKGNvbnN0IGtleSBpbiBmaWxlcykge1xuICAgICAgICAgICAgICAgICAgY29uc3QgdmFsdWUgPSBmaWxlc1trZXldO1xuICAgICAgICAgICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkodmFsdWUpICYmIHZhbHVlLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICAgICAgICAgICAgICBmaWxlc1trZXldID0gdmFsdWVbMF07XG4gICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBmaWxlc1trZXldID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB0aGlzLmVtaXQoJ2VuZCcpO1xuICAgICAgICAgICAgdGhpcy5jYWxsYmFjayhudWxsLCB0aGlzLl9lbWl0UmVzcG9uc2Uob2JqZWN0LCBmaWxlcykpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgdGhpcy5jYWxsYmFjayhlcnIpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgfVxuXG4gICAgdGhpcy5yZXMgPSByZXM7XG5cbiAgICAvLyB1bmJ1ZmZlcmVkXG4gICAgaWYgKCFidWZmZXIpIHtcbiAgICAgIGRlYnVnKCd1bmJ1ZmZlcmVkICVzICVzJywgdGhpcy5tZXRob2QsIHRoaXMudXJsKTtcbiAgICAgIHRoaXMuY2FsbGJhY2sobnVsbCwgdGhpcy5fZW1pdFJlc3BvbnNlKCkpO1xuICAgICAgaWYgKG11bHRpcGFydCkgcmV0dXJuOyAvLyBhbGxvdyBtdWx0aXBhcnQgdG8gaGFuZGxlIGVuZCBldmVudFxuICAgICAgcmVzLm9uY2UoJ2VuZCcsICgpID0+IHtcbiAgICAgICAgZGVidWcoJ2VuZCAlcyAlcycsIHRoaXMubWV0aG9kLCB0aGlzLnVybCk7XG4gICAgICAgIHRoaXMuZW1pdCgnZW5kJyk7XG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyB0ZXJtaW5hdGluZyBldmVudHNcbiAgICByZXMub25jZSgnZXJyb3InLCAoZXJyb3IpID0+IHtcbiAgICAgIHBhcnNlckhhbmRsZXNFbmQgPSBmYWxzZTtcbiAgICAgIHRoaXMuY2FsbGJhY2soZXJyb3IsIG51bGwpO1xuICAgIH0pO1xuICAgIGlmICghcGFyc2VySGFuZGxlc0VuZClcbiAgICAgIHJlcy5vbmNlKCdlbmQnLCAoKSA9PiB7XG4gICAgICAgIGRlYnVnKCdlbmQgJXMgJXMnLCB0aGlzLm1ldGhvZCwgdGhpcy51cmwpO1xuICAgICAgICAvLyBUT0RPOiB1bmxlc3MgYnVmZmVyaW5nIGVtaXQgZWFybGllciB0byBzdHJlYW1cbiAgICAgICAgdGhpcy5lbWl0KCdlbmQnKTtcbiAgICAgICAgdGhpcy5jYWxsYmFjayhudWxsLCB0aGlzLl9lbWl0UmVzcG9uc2UoKSk7XG4gICAgICB9KTtcbiAgfSk7XG5cbiAgdGhpcy5lbWl0KCdyZXF1ZXN0JywgdGhpcyk7XG5cbiAgY29uc3QgZ2V0UHJvZ3Jlc3NNb25pdG9yID0gKCkgPT4ge1xuICAgIGNvbnN0IGxlbmd0aENvbXB1dGFibGUgPSB0cnVlO1xuICAgIGNvbnN0IHRvdGFsID0gcmVxLmdldEhlYWRlcignQ29udGVudC1MZW5ndGgnKTtcbiAgICBsZXQgbG9hZGVkID0gMDtcblxuICAgIGNvbnN0IHByb2dyZXNzID0gbmV3IFN0cmVhbS5UcmFuc2Zvcm0oKTtcbiAgICBwcm9ncmVzcy5fdHJhbnNmb3JtID0gKGNodW5rLCBlbmNvZGluZywgY2FsbGJhY2spID0+IHtcbiAgICAgIGxvYWRlZCArPSBjaHVuay5sZW5ndGg7XG4gICAgICB0aGlzLmVtaXQoJ3Byb2dyZXNzJywge1xuICAgICAgICBkaXJlY3Rpb246ICd1cGxvYWQnLFxuICAgICAgICBsZW5ndGhDb21wdXRhYmxlLFxuICAgICAgICBsb2FkZWQsXG4gICAgICAgIHRvdGFsXG4gICAgICB9KTtcbiAgICAgIGNhbGxiYWNrKG51bGwsIGNodW5rKTtcbiAgICB9O1xuXG4gICAgcmV0dXJuIHByb2dyZXNzO1xuICB9O1xuXG4gIGNvbnN0IGJ1ZmZlclRvQ2h1bmtzID0gKGJ1ZmZlcikgPT4ge1xuICAgIGNvbnN0IGNodW5rU2l6ZSA9IDE2ICogMTAyNDsgLy8gZGVmYXVsdCBoaWdoV2F0ZXJNYXJrIHZhbHVlXG4gICAgY29uc3QgY2h1bmtpbmcgPSBuZXcgU3RyZWFtLlJlYWRhYmxlKCk7XG4gICAgY29uc3QgdG90YWxMZW5ndGggPSBidWZmZXIubGVuZ3RoO1xuICAgIGNvbnN0IHJlbWFpbmRlciA9IHRvdGFsTGVuZ3RoICUgY2h1bmtTaXplO1xuICAgIGNvbnN0IGN1dG9mZiA9IHRvdGFsTGVuZ3RoIC0gcmVtYWluZGVyO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBjdXRvZmY7IGkgKz0gY2h1bmtTaXplKSB7XG4gICAgICBjb25zdCBjaHVuayA9IGJ1ZmZlci5zbGljZShpLCBpICsgY2h1bmtTaXplKTtcbiAgICAgIGNodW5raW5nLnB1c2goY2h1bmspO1xuICAgIH1cblxuICAgIGlmIChyZW1haW5kZXIgPiAwKSB7XG4gICAgICBjb25zdCByZW1haW5kZXJCdWZmZXIgPSBidWZmZXIuc2xpY2UoLXJlbWFpbmRlcik7XG4gICAgICBjaHVua2luZy5wdXNoKHJlbWFpbmRlckJ1ZmZlcik7XG4gICAgfVxuXG4gICAgY2h1bmtpbmcucHVzaChudWxsKTsgLy8gbm8gbW9yZSBkYXRhXG5cbiAgICByZXR1cm4gY2h1bmtpbmc7XG4gIH07XG5cbiAgLy8gaWYgYSBGb3JtRGF0YSBpbnN0YW5jZSBnb3QgY3JlYXRlZCwgdGhlbiB3ZSBzZW5kIHRoYXQgYXMgdGhlIHJlcXVlc3QgYm9keVxuICBjb25zdCBmb3JtRGF0YSA9IHRoaXMuX2Zvcm1EYXRhO1xuICBpZiAoZm9ybURhdGEpIHtcbiAgICAvLyBzZXQgaGVhZGVyc1xuICAgIGNvbnN0IGhlYWRlcnMgPSBmb3JtRGF0YS5nZXRIZWFkZXJzKCk7XG4gICAgZm9yIChjb25zdCBpIGluIGhlYWRlcnMpIHtcbiAgICAgIGlmIChoYXNPd24oaGVhZGVycywgaSkpIHtcbiAgICAgICAgZGVidWcoJ3NldHRpbmcgRm9ybURhdGEgaGVhZGVyOiBcIiVzOiAlc1wiJywgaSwgaGVhZGVyc1tpXSk7XG4gICAgICAgIHJlcS5zZXRIZWFkZXIoaSwgaGVhZGVyc1tpXSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gYXR0ZW1wdCB0byBnZXQgXCJDb250ZW50LUxlbmd0aFwiIGhlYWRlclxuICAgIGZvcm1EYXRhLmdldExlbmd0aCgoZXJyb3IsIGxlbmd0aCkgPT4ge1xuICAgICAgLy8gVE9ETzogQWRkIGNodW5rZWQgZW5jb2Rpbmcgd2hlbiBubyBsZW5ndGggKGlmIGVycilcbiAgICAgIGlmIChlcnJvcikgZGVidWcoJ2Zvcm1EYXRhLmdldExlbmd0aCBoYWQgZXJyb3InLCBlcnJvciwgbGVuZ3RoKTtcblxuICAgICAgZGVidWcoJ2dvdCBGb3JtRGF0YSBDb250ZW50LUxlbmd0aDogJXMnLCBsZW5ndGgpO1xuICAgICAgaWYgKHR5cGVvZiBsZW5ndGggPT09ICdudW1iZXInKSB7XG4gICAgICAgIHJlcS5zZXRIZWFkZXIoJ0NvbnRlbnQtTGVuZ3RoJywgbGVuZ3RoKTtcbiAgICAgIH1cblxuICAgICAgZm9ybURhdGEucGlwZShnZXRQcm9ncmVzc01vbml0b3IoKSkucGlwZShyZXEpO1xuICAgIH0pO1xuICB9IGVsc2UgaWYgKEJ1ZmZlci5pc0J1ZmZlcihkYXRhKSkge1xuICAgIGJ1ZmZlclRvQ2h1bmtzKGRhdGEpLnBpcGUoZ2V0UHJvZ3Jlc3NNb25pdG9yKCkpLnBpcGUocmVxKTtcbiAgfSBlbHNlIHtcbiAgICByZXEuZW5kKGRhdGEpO1xuICB9XG59O1xuXG4vLyBDaGVjayB3aGV0aGVyIHJlc3BvbnNlIGhhcyBhIG5vbi0wLXNpemVkIGd6aXAtZW5jb2RlZCBib2R5XG5SZXF1ZXN0LnByb3RvdHlwZS5fc2hvdWxkVW56aXAgPSAocmVzKSA9PiB7XG4gIGlmIChyZXMuc3RhdHVzQ29kZSA9PT0gMjA0IHx8IHJlcy5zdGF0dXNDb2RlID09PSAzMDQpIHtcbiAgICAvLyBUaGVzZSBhcmVuJ3Qgc3VwcG9zZWQgdG8gaGF2ZSBhbnkgYm9keVxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIC8vIGhlYWRlciBjb250ZW50IGlzIGEgc3RyaW5nLCBhbmQgZGlzdGluY3Rpb24gYmV0d2VlbiAwIGFuZCBubyBpbmZvcm1hdGlvbiBpcyBjcnVjaWFsXG4gIGlmIChyZXMuaGVhZGVyc1snY29udGVudC1sZW5ndGgnXSA9PT0gJzAnKSB7XG4gICAgLy8gV2Uga25vdyB0aGF0IHRoZSBib2R5IGlzIGVtcHR5ICh1bmZvcnR1bmF0ZWx5LCB0aGlzIGNoZWNrIGRvZXMgbm90IGNvdmVyIGNodW5rZWQgZW5jb2RpbmcpXG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgLy8gY29uc29sZS5sb2cocmVzKTtcbiAgcmV0dXJuIC9eXFxzKig/OmRlZmxhdGV8Z3ppcClcXHMqJC8udGVzdChyZXMuaGVhZGVyc1snY29udGVudC1lbmNvZGluZyddKTtcbn07XG5cbi8qKlxuICogT3ZlcnJpZGVzIEROUyBmb3Igc2VsZWN0ZWQgaG9zdG5hbWVzLiBUYWtlcyBvYmplY3QgbWFwcGluZyBob3N0bmFtZXMgdG8gSVAgYWRkcmVzc2VzLlxuICpcbiAqIFdoZW4gbWFraW5nIGEgcmVxdWVzdCB0byBhIFVSTCB3aXRoIGEgaG9zdG5hbWUgZXhhY3RseSBtYXRjaGluZyBhIGtleSBpbiB0aGUgb2JqZWN0LFxuICogdXNlIHRoZSBnaXZlbiBJUCBhZGRyZXNzIHRvIGNvbm5lY3QsIGluc3RlYWQgb2YgdXNpbmcgRE5TIHRvIHJlc29sdmUgdGhlIGhvc3RuYW1lLlxuICpcbiAqIEEgc3BlY2lhbCBob3N0IGAqYCBtYXRjaGVzIGV2ZXJ5IGhvc3RuYW1lIChrZWVwIHJlZGlyZWN0cyBpbiBtaW5kISlcbiAqXG4gKiAgICAgIHJlcXVlc3QuY29ubmVjdCh7XG4gKiAgICAgICAgJ3Rlc3QuZXhhbXBsZS5jb20nOiAnMTI3LjAuMC4xJyxcbiAqICAgICAgICAnaXB2Ni5leGFtcGxlLmNvbSc6ICc6OjEnLFxuICogICAgICB9KVxuICovXG5SZXF1ZXN0LnByb3RvdHlwZS5jb25uZWN0ID0gZnVuY3Rpb24gKGNvbm5lY3RPdmVycmlkZSkge1xuICBpZiAodHlwZW9mIGNvbm5lY3RPdmVycmlkZSA9PT0gJ3N0cmluZycpIHtcbiAgICB0aGlzLl9jb25uZWN0T3ZlcnJpZGUgPSB7ICcqJzogY29ubmVjdE92ZXJyaWRlIH07XG4gIH0gZWxzZSBpZiAodHlwZW9mIGNvbm5lY3RPdmVycmlkZSA9PT0gJ29iamVjdCcpIHtcbiAgICB0aGlzLl9jb25uZWN0T3ZlcnJpZGUgPSBjb25uZWN0T3ZlcnJpZGU7XG4gIH0gZWxzZSB7XG4gICAgdGhpcy5fY29ubmVjdE92ZXJyaWRlID0gdW5kZWZpbmVkO1xuICB9XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS50cnVzdExvY2FsaG9zdCA9IGZ1bmN0aW9uICh0b2dnbGUpIHtcbiAgdGhpcy5fdHJ1c3RMb2NhbGhvc3QgPSB0b2dnbGUgPT09IHVuZGVmaW5lZCA/IHRydWUgOiB0b2dnbGU7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLy8gZ2VuZXJhdGUgSFRUUCB2ZXJiIG1ldGhvZHNcbmlmICghbWV0aG9kcy5pbmNsdWRlcygnZGVsJykpIHtcbiAgLy8gY3JlYXRlIGEgY29weSBzbyB3ZSBkb24ndCBjYXVzZSBjb25mbGljdHMgd2l0aFxuICAvLyBvdGhlciBwYWNrYWdlcyB1c2luZyB0aGUgbWV0aG9kcyBwYWNrYWdlIGFuZFxuICAvLyBucG0gMy54XG4gIG1ldGhvZHMgPSBbLi4ubWV0aG9kc107XG4gIG1ldGhvZHMucHVzaCgnZGVsJyk7XG59XG5cbmZvciAobGV0IG1ldGhvZCBvZiBtZXRob2RzKSB7XG4gIGNvbnN0IG5hbWUgPSBtZXRob2Q7XG4gIG1ldGhvZCA9IG1ldGhvZCA9PT0gJ2RlbCcgPyAnZGVsZXRlJyA6IG1ldGhvZDtcblxuICBtZXRob2QgPSBtZXRob2QudG9VcHBlckNhc2UoKTtcbiAgcmVxdWVzdFtuYW1lXSA9ICh1cmwsIGRhdGEsIGZuKSA9PiB7XG4gICAgY29uc3QgcmVxdWVzdF8gPSByZXF1ZXN0KG1ldGhvZCwgdXJsKTtcbiAgICBpZiAodHlwZW9mIGRhdGEgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgIGZuID0gZGF0YTtcbiAgICAgIGRhdGEgPSBudWxsO1xuICAgIH1cblxuICAgIGlmIChkYXRhKSB7XG4gICAgICBpZiAobWV0aG9kID09PSAnR0VUJyB8fCBtZXRob2QgPT09ICdIRUFEJykge1xuICAgICAgICByZXF1ZXN0Xy5xdWVyeShkYXRhKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJlcXVlc3RfLnNlbmQoZGF0YSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKGZuKSByZXF1ZXN0Xy5lbmQoZm4pO1xuICAgIHJldHVybiByZXF1ZXN0XztcbiAgfTtcbn1cblxuLyoqXG4gKiBDaGVjayBpZiBgbWltZWAgaXMgdGV4dCBhbmQgc2hvdWxkIGJlIGJ1ZmZlcmVkLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBtaW1lXG4gKiBAcmV0dXJuIHtCb29sZWFufVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBpc1RleHQobWltZSkge1xuICBjb25zdCBwYXJ0cyA9IG1pbWUuc3BsaXQoJy8nKTtcbiAgbGV0IHR5cGUgPSBwYXJ0c1swXTtcbiAgaWYgKHR5cGUpIHR5cGUgPSB0eXBlLnRvTG93ZXJDYXNlKCkudHJpbSgpO1xuICBsZXQgc3VidHlwZSA9IHBhcnRzWzFdO1xuICBpZiAoc3VidHlwZSkgc3VidHlwZSA9IHN1YnR5cGUudG9Mb3dlckNhc2UoKS50cmltKCk7XG5cbiAgcmV0dXJuIHR5cGUgPT09ICd0ZXh0JyB8fCBzdWJ0eXBlID09PSAneC13d3ctZm9ybS11cmxlbmNvZGVkJztcbn1cblxuLy8gVGhpcyBpcyBub3QgYSBjYXRjaGFsbCwgYnV0IGEgc3RhcnQuIEl0IG1pZ2h0IGJlIHVzZWZ1bFxuLy8gaW4gdGhlIGxvbmcgcnVuIHRvIGhhdmUgZmlsZSB0aGF0IGluY2x1ZGVzIGFsbCBiaW5hcnlcbi8vIGNvbnRlbnQgdHlwZXMgZnJvbSBodHRwczovL3d3dy5pYW5hLm9yZy9hc3NpZ25tZW50cy9tZWRpYS10eXBlcy9tZWRpYS10eXBlcy54aHRtbFxuZnVuY3Rpb24gaXNCaW5hcnkobWltZSkge1xuICBsZXQgW3JlZ2lzdHJ5LCBuYW1lXSA9IG1pbWUuc3BsaXQoJy8nKTtcbiAgaWYgKHJlZ2lzdHJ5KSByZWdpc3RyeSA9IHJlZ2lzdHJ5LnRvTG93ZXJDYXNlKCkudHJpbSgpO1xuICBpZiAobmFtZSkgbmFtZSA9IG5hbWUudG9Mb3dlckNhc2UoKS50cmltKCk7XG4gIHJldHVybiAoXG4gICAgWydhdWRpbycsICdmb250JywgJ2ltYWdlJywgJ3ZpZGVvJ10uaW5jbHVkZXMocmVnaXN0cnkpIHx8XG4gICAgWydneicsICdnemlwJ10uaW5jbHVkZXMobmFtZSlcbiAgKTtcbn1cblxuLyoqXG4gKiBDaGVjayBpZiBgbWltZWAgaXMganNvbiBvciBoYXMgK2pzb24gc3RydWN0dXJlZCBzeW50YXggc3VmZml4LlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBtaW1lXG4gKiBAcmV0dXJuIHtCb29sZWFufVxuICogQGFwaSBwcml2YXRlXG4gKi9cblxuZnVuY3Rpb24gaXNKU09OKG1pbWUpIHtcbiAgLy8gc2hvdWxkIG1hdGNoIC9qc29uIG9yICtqc29uXG4gIC8vIGJ1dCBub3QgL2pzb24tc2VxXG4gIHJldHVybiAvWy8rXWpzb24oJHxbXi1cXHddKS9pLnRlc3QobWltZSk7XG59XG5cbi8qKlxuICogQ2hlY2sgaWYgd2Ugc2hvdWxkIGZvbGxvdyB0aGUgcmVkaXJlY3QgYGNvZGVgLlxuICpcbiAqIEBwYXJhbSB7TnVtYmVyfSBjb2RlXG4gKiBAcmV0dXJuIHtCb29sZWFufVxuICogQGFwaSBwcml2YXRlXG4gKi9cblxuZnVuY3Rpb24gaXNSZWRpcmVjdChjb2RlKSB7XG4gIHJldHVybiBbMzAxLCAzMDIsIDMwMywgMzA1LCAzMDcsIDMwOF0uaW5jbHVkZXMo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