import { redirect } from 'next/navigation'

export async function GET(request: Request) {
  // Get code from query params
  const searchParams = new URL(request.url).searchParams
  const code = searchParams.get('code')
  const state = searchParams.get('state')

  // Verify state parameter exists
  if (!state) {
    return new Response('Missing state parameter', { status: 400 })
  }

  // Exchange auth code for tokens
  const tokenRequest = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: process.env.NEXT_PUBLIC_SAMSARA_CLIENT_ID || '',
    client_secret: process.env.SAMSARA_CLIENT_SECRET || '',
    code: code || ''
  })

  const response = await fetch('https://api.samsara.com/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
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

  // Log tokens to console
  console.log('Access Token:', access_token)
  console.log('Refresh Token:', refresh_token)
  console.log('Expires In:', expires_in, 'seconds')

  // Return access token to UI
  return new Response(`Access Token: ${access_token}`)
} 