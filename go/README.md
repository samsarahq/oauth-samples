# Samsara OAuth 2.0 Example

This example shows how to implement OAuth 2.0 authorization flow with the Samsara API using Go.

## Prerequisites

- Go 1.16 or higher
- A Samsara account with dashboard access
- Your Application Client ID and Client Secret

## Setup

1. Clone this repository

2. Install the dependencies

```bash
go mod tidy
```

3. Create a `.env` file in the root directory.

```sh
cp .env.example .env
```

with your client ID and client secret.

```yaml
SAMSARA_CLIENT_ID=your_client_id
SAMSARA_CLIENT_SECRET=your_client_secret
```

4. Run the server

```bash
go run server.go
```

5. Navigate to `http://localhost:5000` in your browser.

## Support

If you have any questions or need assistance with the samples, please ask a question in the [Developer Community](https://developers.samsara.com/discuss).