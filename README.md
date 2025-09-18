# InboxKit UID Mapper and Updater (Streamlit)

A professional Streamlit tool to:
1. Upload a CSV of email accounts.
2. Parse `username` and `domain` from each email.
3. Map each email to its InboxKit **UID** using a lookup flow.
4. Preview and manually fix missing UIDs if needed (grab values from the official `/v1/api/mailboxes/list` endpoint when you prefer a manual workflow).
5. Update mailbox fields (`first_name`, `last_name`, `user_name`) via the **/v1/api/mailboxes/update** endpoint.
6. View progress and logs. Download results as CSV.

## Why this solves CORS

All API calls are made server side from Python using `requests`, so browsers do not block calls due to CORS. No client side `fetch` is used. This avoids the usual cross origin errors after deployment.

## Features

- Clean, minimal Streamlit UI.
- Robust CSV parsing with automatic delimiter detection.
- UID mapping workflow with retry logic and manual override editor.
- Update workflow with per row progress and error capture.
- Centralized logging to `logs/app.log` plus on screen tail.
- Fully environment driven configuration. Safe for GitHub Secrets and Streamlit Cloud Secrets.
- MIT licensed.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# Set env vars or copy .env.example to .env
export INBOXKIT_BASE_URL="https://api.inboxkit.com"
export INBOXKIT_BEARER="YOUR_BEARER"
export INBOXKIT_WORKSPACE_ID="YOUR_WORKSPACE_ID"
streamlit run app.py
```

Open the app in your browser, upload a CSV, then follow the two steps: Map UIDs, Update Mailboxes.

## CSV format

Required: `email` column.  
Optional: `first_name`, `last_name`, `user_name`.  
You can select different column names in the UI if your headers differ.

See `sample_data/example.csv` for a template.

## Configuration

The app reads configuration in this order:
- Streamlit `secrets.toml`
- Environment variables

Keys:
- `INBOXKIT_BASE_URL` default `https://api.inboxkit.com`
- `INBOXKIT_BEARER` required
- `INBOXKIT_WORKSPACE_ID` required
- `INBOXKIT_UID_LOOKUP_MODE` `auto` or one of `email`, `search`, `list`

For Streamlit Cloud, copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and fill values.

For GitHub Actions or Codespaces you can store these as repository secrets and export them at runtime.

## UID lookup

Your API spec included the update endpoint. A UID lookup endpoint was not specified. The client implements a pragmatic sequence:
- `GET /v1/api/mailboxes/find?email=...` (mode `email`)
- `GET /v1/api/mailboxes/search?keyword={username}&domain={domain}` (mode `search`)
- `POST /v1/api/mailboxes/list` with `{"page": 1, "limit": 1, "keyword": username, "domain": domain}` and then filters the returned `mailboxes` array for the matching `username@domain` (mode `list`).

Set `INBOXKIT_UID_LOOKUP_MODE` to force one. In `auto` the client tries all three, and the list mode now mirrors the official `/v1/api/mailboxes/list` endpoint behaviour (including the same filter payload). If your actual endpoint differs, change the paths in `inboxkit_client.py` to match your API. The manual override editor in the UI lets you paste UIDs for rows that do not resolve automatically—perfect for values collected directly from the `/v1/api/mailboxes/list` endpoint in your own tooling.

## Error handling

- 401 Unauthorized: check the Bearer token.
- 404 Not found during UID lookup: either mailbox does not exist or the endpoint path is wrong.
- 4xx or 5xx responses are surfaced in the result table and logs.
- List lookups raise a clear `No mailbox matching ...` message when the `/v1/api/mailboxes/list` response does not include the target email.
- Network faults are retried with exponential backoff.

## Deployment

- **Streamlit Cloud**: push this repo, set the three secrets in the app settings, then deploy. No CORS issues because calls are server side.
- **Docker**: optional. Streamlit works fine without a container.
- **GitHub Secrets**: store your keys as `INBOXKIT_BEARER` and `INBOXKIT_WORKSPACE_ID`. Do not hard code secrets in the repo.

## Security

Do not commit secrets. Use environment variables or Streamlit secrets. The app never logs token values.

## License

MIT
