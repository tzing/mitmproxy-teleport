"""
mitmproxy-teleport
==================

A mitmproxy addon that reads TLS parameters from Teleport bastion

License
-------
MIT License

Copyright (c) 2023 tzing

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
from __future__ import annotations

import atexit
import datetime
import functools
import json
import logging
import os
import subprocess
import tempfile
import typing
import urllib.parse

import cryptography.x509
from mitmproxy.addons.tlsconfig import DEFAULT_CIPHERS
from mitmproxy.ctx import options
from mitmproxy.net.tls import Method, Verify, Version, create_proxy_server_context
from OpenSSL import SSL

if typing.TYPE_CHECKING:
    from mitmproxy.connection import Server
    from mitmproxy.tls import TlsData

logger = logging.getLogger(__name__)


class TeleportTlsConfig:
    """
    A addon that reads TLS configurations from Teleport bastion and intergrate
    them into mitmproxy.
    """

    def __init__(
        self,
        app: str,
        *,
        proxy: str | None = None,
        cluster: str | None = None,
        user: str | None = None,
    ) -> None:
        """
        Parameters
        ----------
        app: str
            Teleport application name to request certificate for.
        proxy: str | None
            Address to Teleport proxy service
        cluster: str | None
            Teleport cluster to connect
        user: str | None
            Teleport user name
        """
        logger.info("Read TLS config for %s from Teleport", app)

        tls_config = load_tsh_tls_config(
            proxy=proxy, cluster=cluster, user=user, app=app
        )

        self.hostname, self.port = extract_server_address(tls_config["uri"])
        logger.info("Use Teleport cert for %s:%s", self.hostname, self.port)

        self.cert = create_combined_client_cert(
            path_cert=tls_config["cert"], path_key=tls_config["key"]
        )

    def tls_start_server(self, tls_data: TlsData):
        # https://github.com/mitmproxy/mitmproxy/blob/10.1.1/mitmproxy/addons/tlsconfig.py#L230-L330
        if tls_data.ssl_conn is not None:
            return

        # early escape non-related connections
        client = tls_data.context.client
        server: Server = tls_data.conn

        server_name, server_port = server.address

        match_server = self.hostname == server_name
        match_server &= self.port is None or self.port == server_port
        if not match_server:
            return

        # supply extra information
        if server.sni is None:
            server.sni = client.sni or server.address[0]

        if not server.alpn_offers and client.alpn_offers:
            if options.http2:
                server.alpn_offers = tuple(client.alpn_offers)
            else:
                server.alpn_offers = tuple(x for x in client.alpn_offers if x != b"h2")

        if not server.cipher_list and options.ciphers_server:
            server.cipher_list = options.ciphers_server.split(":")
        cipher_list = server.cipher_list or DEFAULT_CIPHERS

        # setup ssl context
        method = Method.TLS_CLIENT_METHOD
        if tls_data.is_dtls:
            method = Method.DTLS_CLIENT_METHOD

        verify = Verify.VERIFY_PEER
        if options.ssl_insecure:
            verify = Verify.VERIFY_NONE

        ssl_ctx = create_proxy_server_context(
            method=method,
            min_version=Version.TLS1_2,
            max_version=Version.UNBOUNDED,
            cipher_list=cipher_list,
            ecdh_curve=options.tls_ecdh_curve_server,
            verify=verify,
            ca_path=options.ssl_verify_upstream_trusted_confdir,
            ca_pemfile=options.ssl_verify_upstream_trusted_ca,
            client_cert=self.cert,
            legacy_server_connect=options.ssl_insecure,
        )

        tls_data.ssl_conn = SSL.Connection(ssl_ctx)

        if server.alpn_offers:
            tls_data.ssl_conn.set_alpn_protos(server.alpn_offers)

        tls_data.ssl_conn.set_connect_state()


def load_tsh_tls_config(proxy: str, cluster: str, user: str, app: str):
    # attempt get config
    cfg = get_tsh_app_config(app)
    if cfg and is_certificate_valid(cfg["cert"]):
        return cfg

    # login
    login_tsh_app(proxy=proxy, cluster=cluster, user=user, app=app)
    return get_tsh_app_config(app)


def get_tsh_app_config(app: str) -> dict[str, str]:
    res = subprocess.run(
        ["tsh", "app", "config", "--format=json", app], stdout=subprocess.PIPE
    )
    if res.returncode != 0:
        return {}
    return json.loads(res.stdout)


def is_certificate_valid(filepath: str) -> bool:
    with open(filepath, "rb") as fd:
        data = fd.read()

    cert = cryptography.x509.load_pem_x509_certificate(data)
    now = datetime.datetime.utcnow()
    if now > cert.not_valid_after:
        logger.debug(
            "Certificate expire at: %s < current time %s", cert.not_valid_after, now
        )
        return False

    return True


def login_tsh_app(proxy: str, cluster: str, user: str, app: str) -> None:
    cmd = ["tsh", "app", "login", app]
    if proxy:
        cmd.append(f"--proxy={proxy}")
    if cluster:
        cmd.append(f"--cluster={cluster}")
    if user:
        cmd.append(f"--user={user}")

    subprocess.run(cmd, check=True)


def extract_server_address(uri: str) -> tuple[str, int | None]:
    u = urllib.parse.urlsplit(uri)
    host = u.hostname
    port = u.port
    return host, port


@functools.lru_cache(32)
def create_combined_client_cert(path_cert: str, path_key: str) -> str:
    # Teleport provide client cert and key in separated files
    # and mitmproxy reads the combined one
    fd_cert, path_output = tempfile.mkstemp(suffix=".pem")
    atexit.register(os.remove, path_output)

    with open(path_cert, "rb") as fd_src:
        os.write(fd_cert, fd_src.read())
    os.write(fd_cert, b"\n")
    with open(path_key, "rb") as fd_src:
        os.write(fd_cert, fd_src.read())

    return path_output
