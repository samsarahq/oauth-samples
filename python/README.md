# Samsara OAuth 2.0 Example

This example shows how to implement OAuth 2.0 authorization flow with the Samsara API using Python.

## Prerequisites

- Python 3.7 or higher
- A Samsara account with dashboard access
- Your Application Client ID and Client Secret

## Setup

1. Clone this repository

2. Create a `.env` file in the root directory.

```sh
cp .env.example .env
```

Then populate with your OAuth 2.0 credentials:

```sh
SAMSARA_CLIENT_ID=your_client_id
SAMSARA_CLIENT_SECRET=your_client_secret
```

3. Install dependencies:

```sh
pip install -r requirements.txt
```

4. Run the application:

```sh
python server.py
```

5. Navigate to [`http://localhost:5000`](http://localhost:5000) in your browser to see the application in action.

## Support

If you have any questions or need assistance with the samples, please ask a question in the [Developer Community](https://developers.samsara.com/discuss).
