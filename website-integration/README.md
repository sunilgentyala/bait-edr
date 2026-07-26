# Website Integration

The included custom element displays a small read-only status card on an existing website. It uses Shadow DOM so host-page styles do not alter the component.

## Safe integration pattern

1. Keep the BAIT API on a private management network.
2. Create a server-side status endpoint that queries BAIT using protected credentials.
3. Return only approved aggregate fields: `status`, `alerts`, and `response_mode`.
4. Rate-limit and cache the public status endpoint.
5. Load `bait-status-widget.js` from your own static assets and set `data-api-url`.

Do not place a BAIT bearer token, endpoint names, usernames, process data, indicators, or alert evidence in browser code.

## Example

See `embed.html` for the HTML fragment and `nginx-example.conf` for private administrative proxy boundaries.
