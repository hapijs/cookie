'use strict';

const Hapi = require('hapi');
const internals = {};

let uuid = 1;       // Use seq instead of proper unique identifiers for demo only

const users = {
    john: {
        id: 'john',
        password: 'password',
        name: 'John Doe'
    }
};

const home = (request, h) => {

    return '<html><head><title>Login page</title></head><body><h3>Welcome ' +
      request.auth.credentials.name +
      '!</h3><br/><form method="get" action="/logout">' +
      '<input type="submit" value="Logout">' +
      '</form></body></html>';
};

const login = async (request, h) => {

    if (request.auth.isAuthenticated) {
        return h.redirect('/');
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

        return '<html><head><title>Login page</title></head><body>' +
            (message ? '<h3>' + message + '</h3><br/>' : '') +
            '<form method="post" action="/login">' +
            'Username: <input type="text" name="username"><br>' +
            'Password: <input type="password" name="password"><br/>' +
            '<input type="submit" value="Login"></form></body></html>';
    }

    const sid = String(++uuid);

    await request.server.app.cache.set(sid, { account }, 0);
    request.cookieAuth.set({ sid });

    return h.redirect('/');
};

const logout = (request, h) => {

    request.server.app.cache.drop(request.state['sid-example'].sid);
    request.cookieAuth.clear();
    return h.redirect('/');
};

const server = Hapi.server({ port: 8000 });

exports.start = async () => {

    await server.register(require('../'));

    const cache = server.cache({ segment: 'sessions', expiresIn: 3 * 24 * 60 * 60 * 1000 });
    server.app.cache = cache;

    server.auth.strategy('session', 'cookie', {
        password: 'password-should-be-32-characters',
        cookie: 'sid-example',
        redirectTo: '/login',
        isSecure: false,
        validateFunc: async (request, session) => {

            const cached = await cache.get(session.sid);
            const out = {
                valid: !!cached
            };

            if (out.valid) {
                out.credentials = cached.account;
            }

            return out;
        }
    });

    server.auth.default('session');

    server.route([
        { method: 'GET', path: '/', config: { handler: home } },
        { method: ['GET', 'POST'], path: '/login', config: { handler: login, auth: { mode: 'try' }, plugins: { 'hapi-auth-cookie': { redirectTo: false } } } },
        { method: 'GET', path: '/logout', config: { handler: logout } }
    ]);

    await server.start();

    console.log(`Server started at: ${server.info.uri}`);
};

internals.start = async function () {

    try {
        await exports.start();
    }
    catch (err) {
        console.error(err.stack);
        process.exit(1);
    }
};

internals.start();
