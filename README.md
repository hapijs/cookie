<a href="http://hapijs.com"><img src="https://raw.githubusercontent.com/hapijs/assets/master/images/family.png" width="180px" align="right" /></a>

# cookie

[**hapi**](https://github.com/hapijs/hapi) Cookie authentication plugin

[![Build Status](https://secure.travis-ci.org/hapijs/cookie.svg?branch=master)](http://travis-ci.org/hapijs/cookie)

Cookie authentication provides simple cookie-based session management. The user has to be
authenticated via other means, typically a web form, and upon successful authentication
the browser receives a reply with a session cookie. The cookie uses [Iron](https://github.com/hapijs/iron) to encrypt and sign the session content.

Subsequent requests containing the session cookie are authenticated and validated via the provided `validateFunc` in case the cookie's encrypted content requires validation on each request.

It is important to remember a couple of things:

1. Each cookie operates as a bearer token and anyone in possession of the cookie content can use it to impersonate its true owner.
2. Cookies have a practical maximum length. All of the data you store in a cookie is sent to the browser. If your cookie is too long, browsers may not set it. Read more [here](http://webdesign.about.com/od/cookies/f/web-cookies-size-limit.htm) and [here](http://www.ietf.org/rfc/rfc2965.txt). If you need to store more data, store a small amount of identifying data in the cookie and use that as a key to a server-side cache system.

The `'cookie`' scheme takes the following options:

- `cookie` - an object with the following:
  - `name` - the cookie name. Defaults to `'sid'`.
  - `password` - used for Iron cookie encoding. Should be at least 32 characters long.
  - `ttl` - sets the cookie expires time in milliseconds. Defaults to single browser session (ends
    when browser closes). Required when `keepAlive` is `true`.
  - `domain` - sets the cookie Domain value. Defaults to none.
  - `path` - sets the cookie path value. Defaults to none.
  - `clearInvalid` - if `true`, any authentication cookie that fails validation will be marked as
    expired in the response and cleared. Defaults to `false`.
  - `isSameSite` - if `false` omitted. Other options `Strict` or `Lax`. Defaults to `Strict`.
  - `isSecure` - if `false`, the cookie is allowed to be transmitted over insecure connections which
    exposes it to attacks. Defaults to `true`.
  - `isHttpOnly` - if `false`, the cookie will not include the 'HttpOnly' flag. Defaults to `true`.
- `keepAlive` - if `true`, automatically sets the session cookie after validation to extend the
  current session for a new `ttl` duration. Defaults to `false`.
- `redirectTo` - optional login URI or function `function(request)` that returns a URI to redirect unauthenticated requests to. Note that it will only
  trigger when the authentication mode is `'required'`. To enable or disable redirections for a specific route,
  set the route `plugins` config (`{ options: { plugins: { 'hapi-auth-cookie': { redirectTo: false } } } }`).
  Defaults to no redirection.
- `appendNext` - if `redirectTo` is `true`, can be a boolean, string, or object. Defaults to `false`.
    - if set to `true`, a string, or an object, appends the current request path to the query component
      of the `redirectTo` URI
    - set to a string value or set the `name` property in an object to define the parameter name.
      defaults to `'next'`
    - set the `raw` property of the object to `true` to determine the current request path based on
      the raw node.js request object received from the HTTP server callback instead of the processed
      hapi request object
- `async validateFunc` - an optional session validation function used to validate the content of the
  session cookie on each request. Used to verify that the internal session state is still valid
  (e.g. user account still exists). The function has the signature `function(request, session)`
  where:
    - `request` - is the Hapi request object of the request which is being authenticated.
    - `session` - is the session object set via `request.cookieAuth.set()`.

  Must return an object that contains:
    - `valid` - `true` if the content of the session is valid, otherwise `false`.
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

const Hapi = require('@hapi/hapi');


const internals = {};


// Simulate database for demo

internals.users = [
    {
        id: 1,
        name: 'john',
        password: 'password',
    },
];


internals.renderHtml = {
    login: (message) => {

        return `
    <html><head><title>Login page</title></head><body>
    ${message ? '<h3>' + message + '</h3><br/>' : ''}
    <form method="post" action="/login">
      Username: <input type="text" name="username"><br>
      Password: <input type="password" name="password"><br/>
    <input type="submit" value="Login"></form>
    </body></html>
      `;
    },
    home: (name) => {

        return `
    <html><head><title>Login page</title></head><body>
    <h3>Welcome ${name}! You are logged in!</h3>
    <form method="get" action="/logout">
      <input type="submit" value="Logout">
    </form>
    </body></html>
      `;
    }
};


internals.server = async function () {

    const server = Hapi.server({ port: 8000 });

    await server.register(require('@hapi/cookie'));

    server.auth.strategy('session', 'cookie', {

        cookie: {
            name: 'sid-example',

            // Don't forget to change it to your own secret password!
            password: 'password-should-be-32-characters',

            // For working via HTTP in localhost
            isSecure: false
        },

        redirectTo: '/login',

        validateFunc: async (request, session) => {

            const account = internals.users.find((user) => (user.id === session.id));

            if (!account) {
                // Must return { valid: false } for invalid cookies
                return { valid: false };
            }

            return { valid: true, credentials: account };
        }
    });

    server.auth.default('session');

    server.route([
        {
            method: 'GET',
            path: '/',
            options: {
                handler: (request, h) => {

                    return internals.renderHtml.home(request.auth.credentials.name);
                }
            }
        },
        {
            method: 'GET',
            path: '/login',
            options: {
                auth: {
                    mode: 'try'
                },
                plugins: {
                    'hapi-auth-cookie': {
                        redirectTo: false
                    }
                },
                handler: async (request, h) => {

                    if (request.auth.isAuthenticated) {
                        return h.redirect('/');
                    }

                    return internals.renderHtml.login();
                }
            }
        },
        {
            method: 'POST',
            path: '/login',
            options: {
                auth: {
                    mode: 'try'
                },
                handler: async (request, h) => {

                    const { username, password } = request.payload;
                    if (!username || !password) {
                        return internals.renderHtml.login('Missing username or password');
                    }

                    // Try to find user with given credentials

                    const account = internals.users.find(
                        (user) => user.name === username && user.password === password
                    );

                    if (!account) {
                        return internals.renderHtml.login('Invalid username or password');
                    }

                    request.cookieAuth.set({ id: account.id });
                    return h.redirect('/');
                }
            }
        },
        {
            method: 'GET',
            path: '/logout',
            options: {
                handler: (request, h) => {

                    request.cookieAuth.clear();
                    return h.redirect('/');
                }
            }
        }
    ]);

    await server.start();
    console.log(`Server started at: ${server.info.uri}`);
};


internals.start = async function() {

    try {
        await internals.server();
    }
    catch (err) {
        console.error(err.stack);
        process.exit(1);
    }
};

internals.start();
```
