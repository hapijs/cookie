Hapi = require 'hapi'

uuid = 1 #Use seq instead of proper unique identifiers for demo only

users =
    john:
        id: 'john'
        password: 'password'
        name: 'John Doe'


home = (request, reply) ->
    reply '<html><head><title>Login page</title></head><body><h3>Welcome ' \
      + request.auth.credentials.name \
      + '!</h3><br/><form method="get" action="/logout">' \
      + '<input type="submit" value="Logout">' \
      + '</form></body></html>'

login = (request, reply) ->

    if request.auth.isAuthenticated
        return reply.redirect '/'

    message = ''
    account = null

    if request.method == 'post'
        if not request.payload.username or not request.payload.password
            message = 'Missing username or password'
        else
            account = users[request.payload.username]
            if not account or account.password != request.payload.password
                message = 'Invalid username or password'

    if request.method == 'get' or message
        return reply '<html><head><title>Login page</title></head><body>' \
            + (message ? '<h3>' + message + '</h3><br/>' : '') \
            + '<form method="post" action="/login">' \
            + 'Username: <input type="text" name="username"><br>' \
            + 'Password: <input type="password" name="password"><br/>' \
            + '<input type="submit" value="Login"></form></body></html>'

    sid = String ++uuid
    request.server.app.cache.set sid, { account: account }, 0, (err) ->
        if err then reply err

        request.auth.session.set { sid: sid }
        reply.redirect '/'

logout = (request, reply) ->
    request.auth.session.clear()
    reply.redirect '/'

server = new Hapi.Server()
server.connection { port: 8000 }

server.register require('../'), (err) ->

    cache = server.cache { segment: 'sessions', expiresIn: 3 * 24 * 60 * 60 * 1000 }
    server.app.cache = cache

    server.auth.strategy 'session', 'cookie', true, 
        password: 'secret'
        cookie: 'sid-example'
        redirectTo: '/login'
        isSecure: false
        validateFunc: (request, session, callback) ->
            cache.get session.sid, (err, cached) ->
                if err then return callback err, false
                if not cached then return callback null, false

                callback null, true, cached.account

    server.route [
        { method: 'GET', path: '/', config: { handler: home } }, 
        { method: ['GET', 'POST'], path: '/login', config: { handler: login, auth: { mode: 'try' }, plugins: { 'hapi-auth-cookie': { redirectTo: false } } } }, 
        { method: 'GET', path: '/logout', config: { handler: logout } }
    ]

    server.start () ->
        console.log 'Server ready'
