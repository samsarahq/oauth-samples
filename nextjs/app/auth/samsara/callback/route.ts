import { cookies } from 'next/headers'

export async function GET(request: Request) {
  // Get code from query params
  const searchParams = new URL(request.url).searchParams
  const code = searchParams.get('code')
  const state = searchParams.get('state')

  // Verify state parameter exists
  if (!state) {
    return new Response('Missing state parameter', { status: 400 })
  }

  // Verify state parameter matches the one stored in the cookie
  const cookieStore = await cookies()
  const storedState = cookieStore.get('oauth_state')
  if (!storedState || storedState.value !== state) {
    return new Response('State mismatch', { status: 400 })
  }

  // Exchange auth code for tokens
  const tokenRequest = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code || '',
    redirect_uri: 'http://localhost:5000/auth/samsara/callback'
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
    const error = await response.text()
    console.error('Failed to exchange code for tokens:', error)
    return new Response(`Failed to exchange code for tokens: ${error}`, { status: 400 })
  }

  const tokens = await response.json()
  const { access_token, refresh_token, expires_in } = tokens

  // Calculate expires_at timestamp
  const expires_at = Math.floor(Date.now() / 1000) + expires_in

  // Store credentials in cookies
  cookieStore.set('credentials', JSON.stringify({
    access_token,
    refresh_token,
    expires_at
  }), {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  })

  return Response.redirect(new URL('/', process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:5000'))
}
