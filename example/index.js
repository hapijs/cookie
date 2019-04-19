'use strict';

const Cookie = require('..');
const Hapi = require('@hapi/hapi');


const internals = {
    uuid: 1             // Use seq instead of proper unique identifiers for demo only
};


internals.users = {
    john: {
        id: 'john',
        password: 'password',
        name: 'John Doe'
    }
};


internals.home = function (request, h) {

    return '<html><head><title>Login page</title></head><body><h3>Welcome ' +
        request.auth.credentials.name +
        '!</h3><br/><form method="get" action="/logout">' +
        '<input type="submit" value="Logout">' +
        '</form></body></html>';
};


internals.login = async function (request, h) {

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
            account = internals.users[request.payload.username];
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

    const sid = String(++internals.uuid);

    await request.server.app.cache.set(sid, { account }, 0);
    request.cookieAuth.set({ sid });

    return h.redirect('/');
};


internals.logout = function (request, h) {

    request.server.app.cache.drop(request.state['sid-example'].sid);
    request.cookieAuth.clear();
    return h.redirect('/');
};


internals.start = async function () {

    const server = Hapi.server({ port: 8000 });
    await server.register(Cookie);

    const cache = server.cache({ segment: 'sessions', expiresIn: 3 * 24 * 60 * 60 * 1000 });
    server.app.cache = cache;

    server.auth.strategy('session', 'cookie', {
        cookie: {
            name: 'sid-example',
            password: 'password-should-be-32-characters',
            isSecure: false
        },
        redirectTo: '/login',
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
        { method: 'GET', path: '/', config: { handler: internals.home } },
        { method: ['GET', 'POST'], path: '/login', config: { handler: internals.login, auth: { mode: 'try' }, plugins: { 'hapi-auth-cookie': { redirectTo: false } } } },
        { method: 'GET', path: '/logout', config: { handler: internals.logout } }
    ]);

    await server.start();

    console.log(`Server started at: ${server.info.uri}`);
};

internals.start();
