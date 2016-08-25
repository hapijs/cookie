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

    // This is a private page; if the authentication fails (missing cookie for instance),
    // the response will be a 302 redirection to the path given in 'redirectTo' and the
    // handler is not executed at all
    console.log('credentials: ', request.auth.credentials);
    const html = `
        <html>
            <head><title>Private content page</title></head>
            <body>
                <h3>Welcome ${ request.auth.credentials.name }!</h3>
                <a href="/logout">Logout (clear the cookie)</a>
            </body>
        </html>
    `;
    return reply(html);
};

const login = function (request, reply) {

    if (request.auth.isAuthenticated) {
        return reply.redirect('/');
    }

    const html = `
        <html>
            <head><title>Login page</title></head>
            <body>
                <form method="post" action="/login">
                    Username: <input type="text" name="username"><br/>
                    Password: <input type="password" name="password"><br/>
                    <input type="submit" value="Login">
                </form>
            </body>
        </html>
    `;
    return reply(html);
};

const loginData = function (request, reply) {

    if (request.auth.isAuthenticated) {
        return reply.redirect('/');
    }

    let errorMessage = '';
    let account = null;

    if (!request.payload.username || !request.payload.password) {
        errorMessage = 'Missing username or password';
    }
    else {
        account = users[request.payload.username];
        if (!account || account.password !== request.payload.password) {
            errorMessage = 'Invalid username or password';
        }
    }

    if(errorMessage){
        const html = `
            <html>
                <head><title>Login error</title></head>
                <body>
                    <h3>${ errorMessage }</h3>
                    <a href="/login">Click here</a> to try again.
                </body>
            </html>
        `;
        return reply(html);
    }

    // store the account object (credentials) in the cache and send the cookie with the uuid
    const sid = String(++uuid);
    request.server.app.cache.set(sid, { account: account }, 0, (err) => {

        if (err) {
            return reply(err);
        }

        request.cookieAuth.set({ sid: sid });
        return reply.redirect('/');
    });
};

const logout = function (request, reply) {

    request.cookieAuth.clear();
    return reply.redirect('/login');
};

const server = new Hapi.Server();
server.connection({ port: 8000 });

server.register(require('../'), (err) => {

    if (err) {
        throw err;
    }

    // set up a catbox policy (catbox-memory is used by default)
    const cache = server.cache({ segment: 'sessions', expiresIn: 3 * 24 * 60 * 60 * 1000 });
    server.app.cache = cache;

    server.auth.strategy('session', 'cookie', {
        password: 'password-should-be-32-characters',
        cookie: 'sid-example',
        redirectTo: '/login',
        isSecure: false,
        validateFunc: function (request, session, callback) {

            cache.get(session.sid, (err, cached) => {

                if (err) {
                    return callback(err);
                }

                // we pass false in the 2nd argument so in the handler we'll have
                // request.auth.isAuthenticated === false
                if (!cached) {
                    return callback(null, false);
                }

                // the cached object will be available in the handler at request.auth.credentials
                return callback(null, true, cached.account);
            });
        }
    });

    server.route([
        {
            method: 'GET',
            path: '/',
            config: {
                handler: home,
                auth: {
                    strategy: 'session',
                    mode: 'required'
                }
            }
        },
        {
            method: 'GET',
            path: '/login',
            config: {
                handler: login,
                auth: {
                    strategy: 'session',
                    mode: 'try'
                },
                plugins: {
                    'hapi-auth-cookie': {
                        redirectTo: false
                    }
                }
            }
        },
        {
            method: 'POST',
            path: '/login',
            config: {
                handler: loginData,
                auth: {
                    strategy: 'session',
                    mode: 'try'
                },
                plugins: {
                    'hapi-auth-cookie': {
                        redirectTo: false
                    }
                }
            }
        },
        {
            method: 'GET',
            path: '/logout',
            config: {
                handler: logout
            }
        }
    ]);

    server.start(() => {

        console.log('Server running at:', server.info.uri);
    });
});
