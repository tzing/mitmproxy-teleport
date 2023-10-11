# mitmproxy-teleport

A [mitmproxy] addon that reads TLS parameters from [Teleport] bastion, and secure the connection.

[mitmproxy]: https://mitmproxy.org/
[Teleport]: https://goteleport.com/

It reads TLS parameters from [tsh], apply the certificate between upstream server and the proxy.
This allows scripts to easily reach Teleport-protected servers without having everything setup in the script.

[tsh]: https://goteleport.com/docs/connect-your-client/tsh/

> **Note**
>
> Not a production-ready addon

## Usage

1. Prerequisites - You must have `tsh` installed
2. Install this addon

    ```bash
    pip install git+https://github.com/tzing/mitmproxy-teleport.git
    ```

3. Create configuration - create `tsh.py` file on disk

    ```py
    from mitmproxy_teleport import TeleportTlsConfig

    addons = [
        TeleportTlsConfig("app-name")
    ]
    ```

    Read [documents](#api-documents) below for details.

4. Execute the script from mitmproxy

    ```bash
    mitmdump -s ./tsh.py
    ```

    See [mitmproxy doc](https://docs.mitmproxy.org/stable/overview-getting-started/) for more instructions.


## API documents

### TeleportTlsConfig

The basic object that reads TLS configurations from Teleport bastion and intergrate them into mitmproxy.

It compares the target host to the URI read from Teleport. If there is a match, the client credentials are used to connect.
Connections other than this will not be modified or logged.

**Parameters:**

- `app` (str): Teleport application name to request certificate for
- `proxy` (str; optional): Address to Teleport proxy service
- `cluster` (str; optional): Teleport cluster to connect
- `user` (str; optional): Teleport user name

Note that parameters other than `app` are keyword-only parameters.
