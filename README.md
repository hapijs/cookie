### hapi-auth-cookie

[**hapi**](https://github.com/hapijs/hapi) Cookie authentication plugin

[![Build Status](https://secure.travis-ci.org/hapijs/hapi-auth-cookie.png)](http://travis-ci.org/hapijs/hapi-auth-cookie)

Lead Maintainer: [James Weston](https://github.com/jaw187)

Cookie authentication provides a simple cookie-based session management. The user has to be
authenticated via other means, typically a web form, and upon successful authentication,
receive a reply with a session cookie. Subsequent requests containing the session cookie are
authenticated (the cookie uses [Iron](https://github.com/hueniverse/iron) to encrypt and sign the
session content) and validated via the provided `validateFunc` in case the cookie's encrypted
content requires validation on each request. Note that cookie operates as a bearer token and anyone
in possession of the cookie content can use it to impersonate its true owner. The `'cookie`' scheme
takes the following required options:

- `cookie` - the cookie name. Defaults to `'sid'`.
- `password` - used for Iron cookie encoding. Should be at least 32 characters long.
- `ttl` - sets the cookie expires time in milliseconds. Defaults to single browser session (ends
  when browser closes).
- `domain` - sets the cookie Domain value. Defaults to none.
- `path` - sets the cookie path value. Defaults to `/`.
- `clearInvalid` - if `true`, any authentication cookie that fails validation will be marked as
  expired in the response and cleared. Defaults to `false`.
- `keepAlive` - if `true`, automatically sets the session cookie after validation to extend the
  current session for a new `ttl` duration. Defaults to `false`.
- `isSecure` - if `false`, the cookie is allowed to be transmitted over insecure connections which
  exposes it to attacks. Defaults to `true`.
- `isHttpOnly` - if `false`, the cookie will not include the 'HttpOnly' flag. Defaults to `true`.
- `redirectTo` - optional login URI to redirect unauthenticated requests to. Note that using
  `redirectTo` with authentication mode `'try'` will cause the protected endpoint to always
  redirect, voiding `'try'` mode. To set an individual route to use or disable redirections, use
  the route `plugins` config (`{ config: { plugins: { 'hapi-auth-cookie': { redirectTo: false } } } }`).
  Defaults to no redirection.
- `appendNext` - if `true` and `redirectTo` is `true`, appends the current request path to the
  query component of the `redirectTo` URI using the parameter name `'next'`. Set to a string to use
  a different parameter name. Defaults to `false`.
- `redirectOnTry` - if `false` and route authentication mode is `'try'`, authentication errors will
  not trigger a redirection. Requires **hapi** version 6.2.0 or newer. Defaults to `true`;
- `validateFunc` - an optional session validation function used to validate the content of the
  session cookie on each request. Used to verify that the internal session state is still valid
  (e.g. user account still exists). The function has the signature `function(request, session, callback)`
  where:
    - `request` - is the Hapi request object of the request which is being authenticated.
    - `session` - is the session object set via `request.cookieAuth.set()`.
    - `callback` - a callback function with the signature `function(err, isValid, credentials)`
      where:
        - `err` - an internal error.
        - `isValid` - `true` if the content of the session is valid, otherwise `false`.
        - `credentials` - a credentials object passed back to the application in
          `request.auth.credentials`. If value is `null` or `undefined`, defaults to `session`. If
          set, will override the current cookie as if `request.cookieAuth.set()` was called.
- `requestDecoratorName` - *USE WITH CAUTION* an optional name to use with decorating the `request` object.  Defaults to `'cookieAuth'`.  Using multiple decorator names for separate authentication strategies could allow a developer to call the methods for the wrong strategy.  Potentially resulting in unintended authorized access.

When the cookie scheme is enabled on a route, the `request.cookieAuth` objects is decorated with
the following methods:
- `set(session)` - sets the current session. Must be called after a successful login to begin the
  session. `session` must be a non-null object, which is set on successful subsequent
  authentications in `request.auth.credentials` where:
    - `session` - the session object.
- `set(key, value)` - sets a specific object key on the current session (which must already exist)
  where:
    - `key` - session key string.
    - `value` - value to assign key.
- `clear([key])` - clears the current session or session key where:
    - `key` - optional key string to remove a specific property of the session. If none provided,
      defaults to removing the entire session which is used to log the user out.
- `ttl(msecs)` - sets the ttl of the current active session where:
    - `msecs` - the new ttl in milliseconds.

Because this scheme decorates the `request` object with session-specific methods, it cannot be
registered more than once.

```javascript
'use strict';

const Hapi = require('hapi');

let uuid = 1;       // Use seq instead of proper unique identifiers for demo only

const users = {
    john: {
        id: 'john',
        password: 'password',
        name: 'John Doe'
    }
};

const home = function (request, reply) {

    reply('<html><head><title>Login page</title></head><body><h3>Welcome ' +
      request.auth.credentials.name +
      '!</h3><br/><form method="get" action="/logout">' +
      '<input type="submit" value="Logout">' +
      '</form></body></html>');
};

const login = function (request, reply) {

    if (request.auth.isAuthenticated) {
        return reply.redirect('/');
    }

    let message = '';
    let account = null;

    if (request.method === 'post') {

        if (!request.payload.username ||
            !request.payload.password) {

            message = 'Missing username or password';
        }
        else {
            account = users[request.payload.username];
            if (!account ||
                account.password !== request.payload.password) {

                message = 'Invalid username or password';
            }
        }
    }

    if (request.method === 'get' ||
        message) {

        return reply('<html><head><title>Login page</title></head><body>' +
            (message ? '<h3>' + message + '</h3><br/>' : '') +
            '<form method="post" action="/login">' +
            'Username: <input type="text" name="username"><br>' +
            'Password: <input type="password" name="password"><br/>' +
            '<input type="submit" value="Login"></form></body></html>');
    }

    const sid = String(++uuid);
    request.server.app.cache.set(sid, { account: account }, 0, (err) => {

        if (err) {
            reply(err);
        }

        request.cookieAuth.set({ sid: sid });
        return reply.redirect('/');
    });
};

const logout = function (request, reply) {

    request.cookieAuth.clear();
    return reply.redirect('/');
};

const server = new Hapi.Server();
server.connection({ port: 8000 });

server.register(require('../'), (err) => {

    if (err) {
        throw err;
    }

    const cache = server.cache({ segment: 'sessions', expiresIn: 3 * 24 * 60 * 60 * 1000 });
    server.app.cache = cache;

    server.auth.strategy('session', 'cookie', true, {
        password: 'password-should-be-32-characters',
        cookie: 'sid-example',
        redirectTo: '/login',
        isSecure: false,
        validateFunc: function (request, session, callback) {

            cache.get(session.sid, (err, cached) => {

                if (err) {
                    return callback(err, false);
                }

                if (!cached) {
                    return callback(null, false);
                }

                return callback(null, true, cached.account);
            });
        }
    });

    server.route([
        { method: 'GET', path: '/', config: { handler: home } },
        { method: ['GET', 'POST'], path: '/login', config: { handler: login, auth: { mode: 'try' }, plugins: { 'hapi-auth-cookie': { redirectTo: false } } } },
        { method: 'GET', path: '/logout', config: { handler: logout } }
    ]);

    server.start(() => {

        console.log('Server ready');
    });
});
```
