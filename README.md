# Access Token Auth for Home Assistant

This custom component allows you to delegate authentication to a reverse proxy.

This integrations checks the value of a configured cookie and authenticates based on its content, after checking it is valid. The value of the configure username is
checked against usernames already present in Home Assistant internal database. Users have to be created in Home Assistant by hand.

**Use with caution. If misconfigured, this can lead to a Home Assistant instance that anyone can access**

## Installation

Add this repository to [HACS](https://hacs.xyz/).

Update your configuration.yaml file with

```yaml
access_token:
    # Url to JWKS with your public keys / certs
    jwks_url: https://<yourworkspace>.cloudflareaccess.com/cdn-cgi/access/certs
    # Name of the cookie that contains the JWT
    cookie_name: CF_Authorization
    # Expected value for the audience claim
    audience: eefce7c8394f2e1882563d78e1c023f7a0ffb6add7565aca96be2475c3f26253
    # Optional: claim cointaining the username of the user to login, defaults to "sub"
    username_claim_key: email

# Optionally, if something is not working right, add this block below to get more information
logger:
    default: info
    logs:
        custom_components.access_token: debug
```

Afterwards, restart Home Assistant.

## How it works

On boot, two main things are done when the integration is enabled:

1. The default `LoginFlowIndexView` view is replaced. This view is called when you submit the login form. The replacement for this view, `RequestLoginFlowResourceView`, simply adds the HTTP Request to the context. This context is passed to authentication Providers.

    Normally the Request is not included, as none of the providers require it.

2. The Access Token Authentication Provider is injected into the providers, *before* the other authentication providers.

    This ensures that Header auth is tried first, and if it fails the user can still use username/password.


## Help! Everything is broken!

If anything goes wrong or Home Assistant fails to load the component correctly, simply remove the `access_token` block from your configuration file and restart Home Assistant.


## Credits

This project is truly highly inspired and could not have existed without the incredible work from [@BeryJu](https://github.com/BeryJu/hass-auth-header) and [@sidoh](https://gist.github.com/sidoh/479708a8f5a314075b573a9982e333ec). Thank you guys, you rock 🎸.