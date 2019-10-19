const Router = require('./router')

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
    const r = new Router()
    r.post('/register', req => register(req))
    r.post('/login', req => login(req))
    r.post('/logout', req => logout(req))
    r.get('/loginstatus', req => loginStatus(req))
    r.post('/newtime', req => newTime(req))
    r.post('/deletetime', req => deleteTime(req))
    r.get('/', () => new Response('Hello worker!'))
    
    const resp = await r.route(request)
    return resp
  }

// takes a cookie, parses it, and
// returns an object of cookie values
function cookieToObject(cookie) {
  let cookieObj = {}
  const arr = cookie.split(";")
  arr.forEach(item => {
    // since the session contains a base64 string,
    // we can't just split on =. we can just
    // cut the beginning session= out of the
    // string to get the value though
    if (item.includes("session=")) {
      const session = item.slice(8)
      cookieObj.session = session
    } else {
      const keyValueArr = item.split("=")
      cookieObj[keyValueArr[0]] = keyValueArr[1]
    }
  })
  return cookieObj
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

function hexToArrBuff(hex) {
  return new Uint8Array(hex.match(/[\da-f]{2}/gi).map(function (h) {
    return parseInt(h, 16)
  }))
}

function createSalt() {
  const arrBuff = createRandomArrayBuffer(8)
  const salt = createHex(arrBuff)
  return salt
}

// make sure email isn't blank or too long
function validateEmail(email) {
  if (email === "") return new Response("Email cannot be blank", {status: 401})
  if (email.length >= 255) return new Response("Email max length is 254", {status: 401})
}

// make sure password isn't too long or short
function validatePassword(password) {
  if (password.length <= 7) return new Response("Password minimum is 8 characters", {status: 401})
  if (password.length >= 41) return new Response("Password maximum is 41 characters", {status: 401})
}


async function createSession(obj) {
  // create a random base64 string. this will be
  // the id of the session. Then, encode it so
  // you can create a signature of it
  const sessionId = newRandomBase64()
  const encoded = new TextEncoder().encode(sessionId)
  // keep a secret for creating your crypto key
  // convert it to an arrayBuffer for use with
  // the subtlecrypto library
  const SUPERSECRETKEY = await CRYPTO.get("SUPERSECRETKEY")
  const rawData = new TextEncoder().encode(SUPERSECRETKEY)
  // create your key using your secret
  const key = await crypto.subtle.importKey(
      "raw",
      rawData,
      {name: "HMAC", hash: {name: "SHA-256"}},
      false,
      ["sign"]
    );
  // sign the session id with your secret key
  const signature = await crypto.subtle.sign(
      {name: "HMAC", hash: {name: "SHA-256"}},
      key,
      encoded
      );
  // convert your signature from an array buffer
  // to a hex string
  const hashHex = createHex(signature)
  const date = Date.now()
  const session = {
    email: obj.email,
    expires: date + (60 * 60 * 24 * 14)
  }
  // store session in 'session table'
  await SESSIONS.put(sessionId, JSON.stringify(session))
  obj.session = sessionId
  // update user in database with last session they had
  // so old sessions can be cleared later
  await clock_users.put(obj.email, JSON.stringify(obj))
  return `${sessionId}.${hashHex}`
}

async function verifySession(cookie) {
  // turn cookie header into usable object
  const cookieObj = cookieToObject(cookie)
  // split session cookie on dot to get session id and signature
  const arr = cookieObj.session.split(".")
  const sessionId = arr[0]
  const encoded = new TextEncoder().encode(sessionId)
  const signature = hexToArrBuff(arr[1])
  const SUPERSECRETKEY = await CRYPTO.get("SUPERSECRETKEY")
  const rawData = new TextEncoder().encode(SUPERSECRETKEY)
  const key = await crypto.subtle.importKey(
    "raw",
    rawData,
    {name: "HMAC", hash: {name: "SHA-256"}},
    false,
    ["verify"]
  );
  const verified = await crypto.subtle.verify(
    {name: "HMAC", hash: {name: "SHA-256"}},
    key,
    signature,
    encoded
  )
  if (verified) {
    const session = await SESSIONS.get(sessionId, "json")
    if (session.expires < Date().now) {
      await SESSIONS.delete(sessionId)
      return {verified: false}
    }
    return {verified, session}
  } else {
    return {verified}
  }
}

function newRandomBase64() {
  let arr = createRandomArrayBuffer(8)
  let base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(arr)))
  return base64String
}

function createUUID() {
  const arr0 = createRandomArrayBuffer(4)
  const arr1 = createRandomArrayBuffer(2)
  const arr2 = createRandomArrayBuffer(2)
  const arr3 = createRandomArrayBuffer(2)
  const arr4 = createRandomArrayBuffer(6)
  arr2[0] = 0x40 | (arr2[0] & 0xf)
  arr3[0] = 0x80 | (arr3[0] & 0x3f)
  return `${createHex(arr0)}-${createHex(arr1)}-${createHex(arr2)}-${createHex(arr3)}-${createHex(arr4)}`
}

async function login(req) {
  // maybe handle options
  const user = await req.json()
  let {email, password} = user
  const invalidEmail = validateEmail(email)
  if (invalidEmail) return invalidEmail
  const invalidPassword = validatePassword(password)
  if (invalidPassword) return invalidPassword
  // lower case email for searching in KV
  email = email.toLowerCase()
  const regex = /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/
  // validate email is an actual email instead of a random string
  const isEmail = regex.test(email)
  if (isEmail) {
    const sessionUser = await clock_users.get(email, "json")
    if (sessionUser) {
      const PEPPER = await CRYPTO.get("PEPPER")
      const hash = await crypto.subtle.digest("SHA-512", new TextEncoder().encode(`${password}${sessionUser.salt}${PEPPER}`))
      // crypto.subtle.digest gives us an array buffer,
      // we have to convert it into a hexidecimal string
      const hashHex = createHex(hash)
      if (hashHex === sessionUser.password) {
        const session = await createSession(sessionUser)
        const times = await clock_times.get(email, "json")
        const response = new Response("Logged in " + JSON.stringify(times))
        response.headers.append("Set-Cookie", `session=${session}; path=/; HttpOnly; Secure`)
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
  const user = await req.json()
  let {email, password} = user
  const invalidEmail = validateEmail(email)
  if (invalidEmail) return invalidEmail
  const invalidPassword = validatePassword(password)
  if (invalidPassword) return invalidPassword
  email = email.toLowerCase()
  const regex =  /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/
  const isEmail = regex.test(email)
  if (isEmail) {
    const alreadyExists = await clock_users.get(email, "json")
    if (alreadyExists) return new Response("An account with this email already exists")
    user.salt = createSalt()
    const PEPPER = await CRYPTO.get("PEPPER")
    const hash = await crypto.subtle.digest("SHA-512", new TextEncoder().encode(`${password}${user.salt}${PEPPER}`))
    const hashHex = createHex(hash)
    user.email = user.email.toLowerCase()
    user.password = hashHex
    const times = []
    await clock_users.put(user.email, JSON.stringify(user))
    await clock_times.put(user.email, JSON.stringify(times))
    const session = await createSession(user)
    const response = new Response(JSON.stringify(times))
    response.headers.append("Set-Cookie", `session=${session}; path=/; HttpOnly; Secure`)
    return response
  }
  return new Response("Please enter a valid email")
}

async function logout(req) {
  let user = await verifySession(req.headers.get("cookie"))
  if (user.verified === false) {
    const response = new Response("You are not logged in")
    response.headers.set('cookie', '')
    return response
  }
  const kvUser = await clock_users.get(user.session.email, "json")
  await SESSIONS.delete(kvUser.session)
  kvUser.session = ""
  await clock_users.put(user.session.email, JSON.stringify(kvUser))
  return new Response("Logged out")
}

async function loginStatus(req) {
  let user = await verifySession(req.headers.get("cookie"))
  if (user.verified === false) {
    const response = new Response("Session expired, please log in again")
    response.headers.set('cookie', '')
    return response
  }
  return new Response("session is active")
}

async function newTime(req) {
  let cont
  let postedTime
  try {
    postedTime = await req.json()
  } catch(e) {
    return new Response(e)
  }
  let user
  try {
    user = await verifySession(req.headers.get("cookie"))
  } catch(e) {
    return new Response(e)
  }
  if (user.verified === false) {
    const response = new Response("Session expired, please log in again")
    response.headers.set('cookie', '')
    return response
  }
  const times = await clock_times.get(user.session.email, "json")
  if (postedTime._id) {
    const newTimes = times.map(time => {
      if (time._id === postedTime._id) {
        time = postedTime
      }
      return time
    })
    // Currently, if someone posts with an _id, but
    // that ID doesn't exist in KV, it just returns
    // previous times. Unsure how I should handle, considering
    // how KV works. Probably a sign of someone misusing the
    // app if they post without an ID that already exists
    return new Response(JSON.stringify(newTimes))
  } else {
    times.forEach(time => {
      if (time.hours === postedTime.hours && time.minutes === postedTime.minutes && time.seconds === postedTime.seconds && time.ampm === postedTime.ampm) {
        cont = false
      }
    })
  }
  if (cont === false) return new Response("Time already exists. Please edit the days on the old time")
  // check all times for a duplicate time
  const UUID = createUUID()
  postedTime._id = UUID
  times.push(postedTime)
  await clock_times.put(user.session.email, JSON.stringify(times))
  return new Response(JSON.stringify(times))
}

async function deleteTime(req) {
  let postedTime
  try {
    postedTime = await req.json()
  } catch(e) {
    return new Response(e)
  }
  let user
  try {
    user = await verifySession(req.headers.get("cookie"))
  } catch(e) {
    return new Response(e)
  }
  if (user.verified === false) {
    const response = new Response("Session expired, please log in again")
    response.headers.set('cookie', '')
    return response
  }
  const times = await clock_times.get(user.session.email, "json")
  const updatedTimes = times.filter(thing => {
    return thing._id !== postedTime._id
  })
  const resTimes = JSON.stringify(updatedTimes)
  await clock_times.put(user.session.email, resTimes)
  return new Response(resTimes)
}


// delete user
// update password

// define data structures
// make sure all email storage and reads are lower case

// Create session
    // send custom cookie
    /// id.digest
    // save id to user and delete old session every new one
    // when reading cookie, always verify digest
    // https://stackoverflow.com/questions/5522020/how-do-sessions-work-in-express-js-with-node-js
    // make key with raw import / using raw data to make secret key. sign with crypto signing