const Router = require('./router')

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request))
})

function handler(request) {
    const init = {
        headers: { 'content-type': 'application/json' },
    }
    const body = JSON.stringify({ some: 'json' })
    return new Response(body, init)
}

async function handleRequest(request) {
    const r = new Router()
    // Replace with the approriate paths and handlers
    r.post('/login', req => login(req))
    r.post('/register', req => register(req))
    r.get('/test', req => returnBase64(req))
    r.post('.*/foo.*', req => handler(req))
    r.get('/demos/router/foo', req => fetch(req)) // return the response from the origin
    
    r.get('/', () => new Response('Hello worker!')) // return a default message for the root route
    
    const resp = await r.route(request)
    return resp
  }

function createRandomArrayBuffer(len) {
  let arr = new Uint8Array(len)
  crypto.getRandomValues(arr)
  return arr
}

function createHex(arrBuff) {
  const hashArray = Array.from(new Uint8Array(arrBuff));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex
}

function createSalt() {
  const arrBuff = createRandomArrayBuffer(8)
  const secret = createHex(arrBuff)
  return secret
}

async function createSession(obj) {
  const base64 = newRandomBase64()
  const SUPERSECRETKEY = await CRYPTO.get("SUPERSECRETKEY")
  const rawData = new TextEncoder().encode(SUPERSECRETKEY)
  const key = await crypto.subtle.importKey(
      "raw",
      rawData,
      {name: "HMAC", hash: {name: "SHA-256"}},
      false,
      ["sign"]
    );
  const encoded = new TextEncoder().encode(base64)
  const signature = await crypto.subtle.sign(
      "HMAC",
      key,
      encoded
      );
  const hashHex = createHex(signature)
  const date = Date.now()
  const session = {
    user: obj.login,
    expires: date + (60 * 60 * 24 * 14)
  }
  await SESSIONS.put(base64, JSON.stringify(session))
  obj.Session = base64
  await clock_users.put(obj.login, obj)
  return `${base64}.${hashHex}`
}


function newRandomBase64() {
  let arr = createRandomArrayBuffer(8)
  let base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(arr)))
  return base64String
}

function returnBase64() {
  return new Response(newRandomBase64())
}

async function login(req) {
  // maybe handle options
  let user
  try {
    user = await req.json()
  } catch(e) {
    return new Response("Error parsing JSON")
  }
  let {Login, Password} = user
  if (Login === "") {
      return new Response("Login cannot be blank", {status: 401})
  }
  if (Login.length >= 255) {
    return new Response("Email max length is 254", {status: 401})
  }
  if (Password.length <= 7) {
      return new Response("Password minimum is 8 characters", {status: 401})
  }
  if (Password.length >= 41) {
      return new Response("Password maximum is 41 characters", {status: 401})
  }
  Login = Login.toLowerCase()
  const regex = /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/
  const isEmail = regex.test(Login)
  if (isEmail) {
    let sessionUser
    try {
      sessionUser = await clock_users.get(Login, "json")
    } catch(e) {
      return new Response(e)
    }
    if (sessionUser) {
      const PEPPER = await CRYPTO.get("PEPPER")
      const hash = await crypto.subtle.digest("SHA-512", new TextEncoder().encode(`${Password}${sessionUser.Salt}${PEPPER}`))
      const hashArray = Array.from(new Uint8Array(hash))
      const hashHex = hashArray.map(b => b.toString(16).padStart(2,'0')).join('')
      if (hashHex === sessionUser.Password) {
        const sess = createSession(sessionUser)
        const times = await clock_times.get(Login, "json")
        const response = new Response("Logged in " + JSON.stringify(times))
        response.headers.append("Set-Cookie", `session=${sess}; path=/; HttpOnly; Secure`)
        return response
      } else {
        return new Response("Wrong password, please try again")
      }
    } else {
      return new Response("This email is not linked to an account. Please try again or create a new account")
    }
  }
  return new Response("Please enter your email")
}

async function register(req) {
  let user
  try {
    user = await req.json()
  } catch(e)  {
    return new Response("Error parsing JSON")
  }
  let {Login, Password} = user
  if (Login === "") {
      return new Response("Login cannot be blank", {status: 401})
  }
  if (Login.length >= 255) {
    return new Response("Email max length is 254", {status: 401})
  }
  if (Password.length <= 7) {
      return new Response("Password minimum is 8 characters", {status: 401})
  }
  if (Password.length >= 41) {
      return new Response("Password maximum is 41 characters", {status: 401})
  }
  Login = Login.toLowerCase()
  const regex =  /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/
  const isEmail = regex.test(Login)
  if (isEmail) {
    const alreadyExists = await clock_users.get(Login, "json")
    if (alreadyExists) {
      return new Response("An account with this email already exists")
    }
    user.Salt = createSalt()
    const PEPPER = await CRYPTO.get("PEPPER")
    const hash = await crypto.subtle.digest("SHA-512", new TextEncoder().encode(`${Password}${user.Salt}${PEPPER}`))
    const hashArray = Array.from(new Uint8Array(hash))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2,'0')).join('')
    user.login = user.login.toLowerCase()
    user.Password = hashHex
    await clock_users.put(user.login, JSON.stringify(user))
    await clock_times.put(user.login, JSON.stringify([]))
    const sess = createSession()
    const response = new Response("User has been created")
    response.headers.append("Set-Cookie", `session=${sess}; path=/; HttpOnly; Secure`)
    return response
  }
  return new Response("Please enter a valid email")
}

async function newTime(req) {
  // parse cookie for Login
}

// new time
// edit time
// delete time
// delete user
// update password


// Create session
    // send custom cookie
    /// id.digest
    // save id to user and delete old session every new one
    // when reading cookie, always verify digest
    // https://stackoverflow.com/questions/5522020/how-do-sessions-work-in-express-js-with-node-js
    // make key with raw import / using raw data to make secret key. sign with crypto signing