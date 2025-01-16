import { cookies } from 'next/headers'

export async function GET() {
  const cookieStore = cookies()
  const credentialsCookie = cookieStore.get('credentials')

  if (!credentialsCookie) {
    return new Response('Not authenticated', { status: 401 })
  }

  const credentials = JSON.parse(credentialsCookie.value)
  let { access_token, refresh_token, expires_at } = credentials

  // Check if token is expired or will expire in next 60 seconds
  const now = Math.floor(Date.now() / 1000)
  if (expires_at - now < 60) {
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
    access_token = tokens.access_token
    refresh_token = tokens.refresh_token
    expires_at = Math.floor(Date.now() / 1000) + tokens.expires_in

    // Update stored credentials
    cookieStore.set('credentials', JSON.stringify({
      access_token,
      refresh_token,
      expires_at
    }), {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    })
  }

  // Make the API call to /me endpoint
  const meResponse = await fetch('https://api.samsara.com/me', {
    headers: {
      'Authorization': `Bearer ${access_token}`
    }
  })

  if (!meResponse.ok) {
    return new Response('Failed to fetch user data', { status: meResponse.status })
  }

  const userData = await meResponse.json()
  return Response.json(userData)
}
