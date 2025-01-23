# Samsara OAuth 2.0 Example

This example shows how to implement OAuth 2.0 authorization flow with the Samsara API using Node.js.

## Prerequisites

- Node.js 16 or higher
- A Samsara account with dashboard access
- Your Application Client ID and Client Secret

## Setup

1. Clone this repository

2. Create a `.env` file in the root directory.

```sh
cp .env.example .env
```

3. Add your client ID and client secret to the `.env` file.

```yaml
SAMSARA_CLIENT_ID=your_client_id
SAMSARA_CLIENT_SECRET=your_client_secret
```

4. Install the dependencies

```sh
npm install
```

5. Run the server

```sh
node server.js
```

6. Navigate to `http://localhost:5000` in your browser.

## Support

If you have any questions or need assistance with the samples, please ask a question in the [Developer Community](https://developers.samsara.com/discuss).
