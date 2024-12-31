import { redirect } from 'next/navigation'

export async function GET() {
  // Generate random state parameter for CSRF protection
  const state = crypto.randomUUID()
  
  // Build authorization URL with required parameters
  const authUrl = new URL('https://api.samsara.com/oauth2/authorize')
  const params = new URLSearchParams({
    client_id: process.env.NEXT_PUBLIC_SAMSARA_CLIENT_ID || '',
    response_type: 'code',
    state: state
  })
  authUrl.search = params.toString()

  // Redirect to Samsara OAuth page
  return redirect(authUrl.toString())
} 