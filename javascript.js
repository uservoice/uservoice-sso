import crypto from 'crypto'
import moment from 'moment'

export default (user) => {
  if (!user.expires) {
    user.expires = moment().add(1, 'days').format('YYYY-MM-DD hh:mm:ss') // example expiration one day from now
  }

  const mode = 'AES-128-CBC'
  const ssoKey = process.env.USERVOICE_API_KEY
  const accountKey = process.env.USERVOICE_ACCOUNT_KEY
  const initVector = 'OpenSSL for Ruby'

  user = Buffer.from(JSON.stringify(user))
  const iv = Buffer.from(initVector)

  Array(16).fill().forEach((i) => {
    user[i] ^= iv[i]
  })

  const saltedHash = crypto
    .createHash('sha1')
    .update((ssoKey + accountKey), 'utf-8')
    .digest()
    .slice(0, 16)

  const padLen = 16 - user.length % 16

  Array(padLen).fill().forEach((i) => {
    user += String.fromCharCode(padLen)
  })

  const cipher = crypto.createCipheriv(mode, saltedHash, iv)
  cipher.setAutoPadding(false)
  const token = cipher.update(Buffer.from(user, 'utf-8'), 'utf-8')
  const encoded = encodeURIComponent(token.toString('base64'))
  return encoded
}

// USAGE
import uservoiceSSO from './uservoiceSSO'
const encoded = uservoiceSSO({
  avatar_url
, display_name
, email
, expires
, guid
, trusted
, url
})
res.redirect(`https://foo.bar?sso=${encoded}`) // express res object
