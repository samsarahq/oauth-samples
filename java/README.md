# Samsara OAuth 2.0 Example

This example shows how to implement OAuth 2.0 authorization flow with the Samsara API using Java.

## Prerequisites

- Java 17 or higher
- Maven 3.6 or higher
- A Samsara account with dashboard access
- Your Application Client ID and Client Secret

## Setup

1. Clone this repository

2. Create a `.env` file in the root directory.

```sh
cp .env.example .env
```

3. Add your Client ID and Client Secret to the `.env` file.

```yaml
SAMSARA_CLIENT_ID=your_client_id
SAMSARA_CLIENT_SECRET=your_client_secret
```

4. Install dependencies with Maven

```sh
mvn package
```

5. Run the server

```sh
java -cp target/oauth2-example-1.0-SNAPSHOT.jar com.samsara.dev.Server
```

6. Navigate to `http://localhost:5000` in your browser.

## Support

If you have any questions or need assistance with the samples, please ask a question in the [Developer Community](https://developers.samsara.com/discuss).