package googledomains

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
)

func init() {
	caddy.RegisterModule(Provider{})
}

// Provider lets Caddy read and manipulate DNS records hosted by this DNS provider.
type Provider struct {
	AccessToken        string `json:"access_token,omitempty"`
	KeepExpiredRecords bool   `json:"keep_expired_records,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.google_domains",
		New: func() caddy.Module { return new(Provider) },
	}
}

// Provision sets up the module. Implements caddy.Provisioner.
func (p *Provider) Provision(ctx caddy.Context) error {
	p.AccessToken = caddy.NewReplacer().ReplaceAll(p.AccessToken, "")
	return nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.acmeTXTRecordAPIRequest(ctx, zone, records, "add")
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.acmeTXTRecordAPIRequest(ctx, zone, records, "remove")
}

func (p *Provider) acmeTXTRecordAPIRequest(ctx context.Context, zone string, records []libdns.Record, addOrRemove string) ([]libdns.Record, error) {
	payload, err := p.makePayload(zone, records, addOrRemove)
	if err != nil {
		return nil, err
	}

	resp, err := doRequest(ctx, zone, payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := handleResponse(resp); err != nil {
		return nil, err
	}

	return records, nil
}

func (p *Provider) makePayload(zone string, records []libdns.Record, addOrRemove string) (rotateChallengesBody, error) {
	if addOrRemove != "add" && addOrRemove != "remove" {
		return rotateChallengesBody{}, fmt.Errorf("can only add or remove; unrecognized: %s", addOrRemove)
	}

	// TODO: the Google Domains API is very limited in what kinds of records it supports; return error if unsupported

	payload := rotateChallengesBody{
		AccessToken:        p.AccessToken,
		KeepExpiredRecords: p.KeepExpiredRecords,
	}

	// choose the correct field on the struct to which to append records
	dest := &payload.RecordsToAdd
	if addOrRemove == "remove" {
		dest = &payload.RecordsToRemove
	}

	// convert incoming record types to the format the API requires
	for _, rec := range records {
		*dest = append(*dest, acmeTXTRecord{
			FQDN:   libdns.AbsoluteName(rec.Name, zone),
			Digest: rec.Value,
		})
	}

	return payload, nil
}

func doRequest(ctx context.Context, zone string, payload rotateChallengesBody) (*http.Response, error) {
	uri := fmt.Sprintf("%s%s:rotateChallenges", apiBase, zone)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(payloadJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	return http.DefaultClient.Do(req)
}

func handleResponse(resp *http.Response) error {
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	var info errorResponse
	err := json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return fmt.Errorf("reading error body: %v", err)
	}

	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, info.Error.Message)
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	google_domains <access_token>
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		p.AccessToken = d.Val()
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

type rotateChallengesBody struct {
	AccessToken        string          `json:"accessToken"`
	RecordsToAdd       []acmeTXTRecord `json:"recordsToAdd,omitempty"`
	RecordsToRemove    []acmeTXTRecord `json:"recordsToRemove,omitempty"`
	KeepExpiredRecords bool            `json:"keepExpiredRecords,omitempty"`
}

type acmeTXTRecord struct {
	FQDN       string `json:"fqdn"`
	Digest     string `json:"digest"`
	UpdateTime string `json:"updateTime,omitempty"`
}

type errorResponse struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
		Details []struct {
			Type            string `json:"@type"`
			FieldViolations []struct {
				Description string `json:"description"`
			} `json:"fieldViolations"`
		} `json:"details"`
	} `json:"error"`
}

// API Reference: https://developers.google.com/domains/acme-dns/reference/rest
const apiBase = "https://acmedns.googleapis.com/v1/acmeChallengeSets/"

// Interface guards
var (
	_ caddyfile.Unmarshaler     = (*Provider)(nil)
	_ caddy.Provisioner         = (*Provider)(nil)
	_ certmagic.ACMEDNSProvider = (*Provider)(nil)
)
