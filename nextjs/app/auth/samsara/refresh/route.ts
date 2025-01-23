import { cookies } from 'next/headers'

export async function GET() {
  const cookieStore = cookies()
  const credentialsCookie = cookieStore.get('credentials')

  if (!credentialsCookie) {
    return new Response('Not authenticated', { status: 401 })
  }

  const credentials = JSON.parse(credentialsCookie.value)
  const { refresh_token } = credentials

  // Refresh the token
  const tokenRequest = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refresh_token
  })

  const auth = Buffer.from(process.env.SAMSARA_CLIENT_ID + ':' + process.env.SAMSARA_CLIENT_SECRET).toString('base64')

  const response = await fetch('https://api.samsara.com/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${auth}`
    },
    body: tokenRequest
  })

  if (!response.ok) {
    return new Response('Failed to refresh token', { status: 401 })
  }

  const tokens = await response.json()
  const { access_token, refresh_token: new_refresh_token, expires_in } = tokens

  // Calculate expires_at timestamp
  const expires_at = Math.floor(Date.now() / 1000) + expires_in

  // Store updated credentials in cookies
  cookieStore.set('credentials', JSON.stringify({
    access_token,
    refresh_token: new_refresh_token,
    expires_at
  }), {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  })

  return Response.redirect(new URL('/', process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:5000'))
}
