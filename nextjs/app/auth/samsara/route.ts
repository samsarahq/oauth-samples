export async function GET() {
  // Generate random state parameter for CSRF protection
  const state = crypto.randomUUID()

  // Build authorization URL with required parameters
  const authUrl = new URL('https://api.samsara.com/oauth2/authorize')
  const params = new URLSearchParams({
    client_id: process.env.SAMSARA_CLIENT_ID || '',
    response_type: 'code',
    state: state,
    redirect_uri: 'http://localhost:5000/auth/samsara/callback'
  })
  authUrl.search = params.toString()

  // Store state in cookie for CSRF validation
  return new Response(null, {
    status: 302,
    headers: {
      'Location': authUrl.toString(),
      'Set-Cookie': `oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax`
    }
  })
}