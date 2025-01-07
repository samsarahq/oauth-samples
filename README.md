# Samsara OAuth 2.0 Samples

This repository contains examples for authenticating to Samsara's APIs using OAuth 2.0 to build marketplace apps. Marketplace apps let you create solutions that many Samsara customers can use. If you're building a custom in-house integration for your organization create an API token instead.

[Samsara OAuth 2.0 Documentation](https://developers.samsara.com/docs/oauth-20)

## Getting Started

### Prerequisites

To get started, you'll need the OAuth Client ID and OAuth Client Secret for a Samsara app which you can create from the Samsara Dashboard. **Settings** > **OAuth 2.0 Apps** > **Create App**

We'll use local `.env` files to store the OAuth Client ID and OAuth Client Secret and load them as environment variables. Each example has its own `.env.example` file that you can copy and rename to `.env` and populate with your OAuth Client ID and OAuth Client Secret.

```sh
cp .env.example .env
```

### Overview

These examples show how you might implement these features of a marketplace app:

- `GET /` - A landing page that shows an access token if authenticated and a link to `/auth/samsara` to start the authorization flow.
- `GET /auth/samsara` - Returns a redirect to Samsara's OAuth 2.0 authorization flow.
- `GET /auth/samsara/callback` - Handles the callback from Samsara's OAuth 2.0 authorization flow.
- `GET /auth/samsara/refresh` - Refreshes the access token.
- `GET /auth/samsara/revoke` - Revokes the access token.

### How to run the examples

Each example has its own README file with instructions for installing dependencies and running the example.

## Support

If you have any questions or need assistance with the samples, please ask a question in the [Developer Community](https://developers.samsara.com/discuss).