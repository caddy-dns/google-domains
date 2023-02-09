Google Domains module for Caddy
===========================

This package contains a DNS provider module for [Caddy](https://github.com/caddyserver/caddy). It can be used to manage ACME DNS challenge records with Google Domains.

**Unlike most DNS provider modules for Caddy, this module works ONLY for ACME DNS challenges, due to limitations in the Google Domains API, which is designed only for manipulating TXT records for the DNS challenge.**

## Caddy module name

```
dns.providers.google_domains
```

## Config examples

To use this module for the ACME DNS challenge, [configure the ACME issuer in your Caddy JSON](https://caddyserver.com/docs/json/apps/tls/automation/policies/issuer/acme/) like so:

```json
{
	"module": "acme",
	"challenges": {
		"dns": {
			"provider": {
				"name": "google_domains",
				"access_token": "YOUR_ACCESS_TOKEN"
			}
		}
	}
}
```

or with the Caddyfile:

```
# globally
{
	acme_dns google_domains <access_token>
}
```

```
# one site
tls {
	dns google_domains <access_token>
}
```
