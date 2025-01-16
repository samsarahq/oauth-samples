import { cookies } from 'next/headers'

export async function GET() {
  const cookieStore = await cookies()
  const credentials = JSON.parse(cookieStore.get('credentials')?.value || "{}")

  if (!credentials) {
    return new Response('Not authenticated', { status: 401 })
  }

  const { refresh_token } = credentials

  // Revoke the token
  const tokenRequest = new URLSearchParams({
    token: refresh_token,
  })

  const auth = Buffer.from(process.env.SAMSARA_CLIENT_ID + ':' + process.env.SAMSARA_CLIENT_SECRET).toString('base64')

  const response = await fetch('https://api.samsara.com/oauth2/revoke', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${auth}`
    },
    body: tokenRequest
  })

  if (!response.ok) {
    return new Response('Failed to revoke token', { status: response.status })
  }

  // Delete the credentials cookie
  cookieStore.delete('credentials')

  return Response.redirect(new URL('/', process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:5000'))
}
