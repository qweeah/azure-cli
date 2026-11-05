# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""Minimal anonymous OCI registry client used by `az aks install-cli` to download client binaries
(kubelogin) published as OCI artifacts. See the artifact contract in the AKS package sync:
one image index per `vX.Y.Z` tag, one manifest per os/architecture whose single layer is the
upstream release zip, which contains exactly one file (the binary)."""

import hashlib
import os
import re
import time
import zipfile

import requests
from azure.cli.core.azclierror import ClientRequestError
from knack.log import get_logger

logger = get_logger(__name__)

MEDIA_TYPE_OCI_INDEX = "application/vnd.oci.image.index.v1+json"
MEDIA_TYPE_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MEDIA_TYPE_DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
ANNOTATION_TITLE = "org.opencontainers.image.title"

_RETRY_STATUS_CODES = (429, 500, 502, 503, 504)
_STABLE_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
_BEARER_PARAM = re.compile(r'(\w+)="([^"]*)"')
_LINK_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="?next"?')
_CHUNK_SIZE = 1024 * 1024


def parse_bearer_challenge(header):
    """Parse a `WWW-Authenticate: Bearer realm=...,service=...,scope=...` header."""
    if not header or not header.lower().startswith("bearer "):
        raise ClientRequestError("Unsupported registry authentication challenge: {}".format(header))
    return dict(_BEARER_PARAM.findall(header))


def latest_stable_tag(tags):
    """Return the highest `vX.Y.Z` tag; pre-release and other tags are ignored."""
    versions = []
    for tag in tags or []:
        match = _STABLE_TAG.match(tag)
        if match:
            versions.append((tuple(int(part) for part in match.groups()), tag))
    if not versions:
        return None
    return max(versions)[1]


def select_platform(index, os_name, architecture):
    """Return the manifest descriptor of the image index entry matching os/architecture."""
    for descriptor in index.get("manifests", []):
        platform = descriptor.get("platform") or {}
        if platform.get("os") == os_name and platform.get("architecture") == architecture:
            return descriptor
    return None


def get_archive_layer(manifest):
    """Return the descriptor of the single zip layer of a client binary manifest.

    The layer is identified by its title (the release asset name, `*.zip`); media types are the
    oras defaults and are not part of the contract."""
    layers = manifest.get("layers") or []
    titles = [(layer.get("annotations") or {}).get(ANNOTATION_TITLE, "") for layer in layers]
    if len(layers) != 1 or not titles[0].lower().endswith(".zip"):
        raise ClientRequestError(
            "Unexpected artifact format: expected one '*.zip' layer, got {}.".format(titles))
    return layers[0]


def extract_single_file(archive_path, expected_member, destination):
    """Extract `expected_member` from a zip that must contain exactly that one file."""
    try:
        with zipfile.ZipFile(archive_path) as archive:
            files = [info for info in archive.infolist() if not info.is_dir()]
            if len(files) != 1 or files[0].filename != expected_member:
                raise ClientRequestError("Unexpected archive content: expected only '{}', got {}.".format(
                    expected_member, [info.filename for info in files]))
            with archive.open(files[0]) as src, open(destination, "wb") as dst:
                while True:
                    chunk = src.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    dst.write(chunk)
    except zipfile.BadZipFile as ex:
        raise ClientRequestError("Downloaded archive is not a valid zip: {}".format(ex)) from ex


class OciRegistryClient:
    """Anonymous pull client for one repository of an OCI distribution registry."""

    def __init__(self, registry, repository, session=None, timeout=(10, 60), retries=3, backoff=1.0):
        self.registry = registry
        self.repository = repository
        self.session = session or requests.Session()
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self._token = None

    @property
    def reference(self):
        return "{}/{}".format(self.registry, self.repository)

    def _url(self, path):
        return "https://{}/v2/{}/{}".format(self.registry, self.repository, path)

    def _send(self, url, headers, stream):
        headers = dict(headers or {})
        if self._token:
            headers["Authorization"] = "Bearer {}".format(self._token)
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                response = self.session.get(url, headers=headers, stream=stream, timeout=self.timeout,
                                            allow_redirects=True)
            except (requests.ConnectionError, requests.Timeout) as ex:
                last_error = ex
            else:
                if response.status_code not in _RETRY_STATUS_CODES:
                    return response
                last_error = "HTTP {}".format(response.status_code)
                response.close()
            if attempt < self.retries:
                time.sleep(self.backoff * (2 ** attempt))
        raise ClientRequestError("Failed to reach registry {} ({}): {}".format(self.registry, url, last_error))

    def _authenticate(self, challenge_header):
        params = parse_bearer_challenge(challenge_header)
        realm = params.get("realm")
        if not realm:
            raise ClientRequestError("Registry {} returned no token realm.".format(self.registry))
        query = {"service": params.get("service"), "scope": "repository:{}:pull".format(self.repository)}
        response = self.session.get(realm, params=query, timeout=self.timeout)
        if response.status_code != 200:
            raise ClientRequestError("Failed to get an anonymous token from {} (HTTP {}).".format(
                realm, response.status_code))
        body = response.json()
        self._token = body.get("token") or body.get("access_token")
        if not self._token:
            raise ClientRequestError("Registry {} returned no anonymous token.".format(self.registry))

    def get(self, url, headers=None, stream=False):
        response = self._send(url, headers, stream)
        if response.status_code == 401 and not self._token:
            challenge = response.headers.get("WWW-Authenticate")
            response.close()
            self._authenticate(challenge)
            response = self._send(url, headers, stream)
        return response

    def list_tags(self):
        tags = []
        url = self._url("tags/list")
        while url:
            response = self.get(url)
            if response.status_code != 200:
                raise ClientRequestError("Failed to list tags of {} (HTTP {}).".format(
                    self.reference, response.status_code))
            tags.extend(response.json().get("tags") or [])
            match = _LINK_NEXT.search(response.headers.get("Link", ""))
            url = requests.compat.urljoin(url, match.group(1)) if match else None
        return tags

    def resolve_latest_version(self):
        tag = latest_stable_tag(self.list_tags())
        if not tag:
            raise ClientRequestError("No released version found in {}.".format(self.reference))
        return tag

    def get_manifest(self, reference, accept):
        response = self.get(self._url("manifests/{}".format(reference)), headers={"Accept": ", ".join(accept)})
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise ClientRequestError("Failed to get manifest {}:{} (HTTP {}).".format(
                self.reference, reference, response.status_code))
        content = response.content
        if reference.startswith("sha256:"):
            _verify_digest(content, reference, "manifest {}".format(reference))
        return response.json()

    def get_platform_manifest(self, tag, os_name, architecture):
        index = self.get_manifest(tag, [MEDIA_TYPE_OCI_INDEX, MEDIA_TYPE_DOCKER_LIST])
        if index is None:
            raise ClientRequestError("Version {} was not found in {}.".format(tag, self.reference))
        descriptor = select_platform(index, os_name, architecture)
        if descriptor is None:
            raise ClientRequestError("{}:{} is not available for platform {}/{}.".format(
                self.reference, tag, os_name, architecture))
        manifest = self.get_manifest(descriptor["digest"], [MEDIA_TYPE_OCI_MANIFEST])
        if manifest is None:
            raise ClientRequestError("Manifest {} was not found in {}.".format(descriptor["digest"], self.reference))
        return manifest

    def download_blob(self, descriptor, destination):
        """Stream a blob to `destination`, verifying its size and sha256 digest."""
        digest = descriptor["digest"]
        response = self.get(self._url("blobs/{}".format(digest)), stream=True)
        if response.status_code != 200:
            raise ClientRequestError("Failed to download blob {} from {} (HTTP {}).".format(
                digest, self.reference, response.status_code))
        sha256 = hashlib.sha256()
        size = 0
        with response, open(destination, "wb") as f:
            for chunk in response.iter_content(chunk_size=_CHUNK_SIZE):
                if chunk:
                    sha256.update(chunk)
                    size += len(chunk)
                    f.write(chunk)
        expected_size = descriptor.get("size")
        if expected_size is not None and size != expected_size:
            raise ClientRequestError("Size mismatch for blob {}: expected {}, got {}.".format(
                digest, expected_size, size))
        if "sha256:" + sha256.hexdigest() != digest:
            raise ClientRequestError("Digest mismatch for blob {}: got sha256:{}.".format(digest, sha256.hexdigest()))


def _verify_digest(content, digest, what):
    if not digest.startswith("sha256:"):
        raise ClientRequestError("Unsupported digest algorithm for {}: {}".format(what, digest))
    actual = "sha256:" + hashlib.sha256(content).hexdigest()
    if actual != digest:
        raise ClientRequestError("Digest mismatch for {}: got {}.".format(what, actual))


def install_binary_from_registry(registry, repository, version, os_name, architecture, archive_member,
                                 install_location):
    """Download the release zip for os/architecture, extract `archive_member` and atomically replace
    `install_location`.

    `version` is a tag such as `v0.2.22`, or `latest` to use the highest released tag.
    On any failure the existing file at `install_location` is left untouched."""
    client = OciRegistryClient(registry, repository)
    if version == "latest":
        version = client.resolve_latest_version()
        logger.warning('No version specified, will install the latest version "%s" from "%s"', version,
                       client.reference)
    manifest = client.get_platform_manifest(version, os_name, architecture)
    layer = get_archive_layer(manifest)
    logger.warning('Downloading client to "%s" from "%s:%s" (%s/%s)', install_location, client.reference,
                   version, os_name, architecture)
    install_dir = os.path.dirname(os.path.abspath(install_location))
    prefix = os.path.join(install_dir, ".{}.{}".format(os.path.basename(install_location), os.getpid()))
    archive_path, binary_path = prefix + ".zip", prefix + ".download"
    try:
        client.download_blob(layer, archive_path)
        extract_single_file(archive_path, archive_member, binary_path)
        os.replace(binary_path, install_location)
    finally:
        for path in (archive_path, binary_path):
            if os.path.exists(path):
                os.remove(path)
    return version
