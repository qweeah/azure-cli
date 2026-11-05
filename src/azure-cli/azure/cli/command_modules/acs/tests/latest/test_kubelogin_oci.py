# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile
from unittest import mock

import requests
from azure.cli.command_modules.acs._kubelogin_oci import (
    MEDIA_TYPE_OCI_INDEX,
    OciRegistryClient,
    extract_single_file,
    get_archive_layer,
    install_binary_from_registry,
    latest_stable_tag,
    parse_bearer_challenge,
    select_platform,
)
from azure.cli.core.azclierror import ClientRequestError

REGISTRY = "registry.example"
REPO = "aks/packages/kubernetes/kubelogin"
CHALLENGE = 'Bearer realm="https://registry.example/oauth2/token",service="registry.example",scope="x"'
PLATFORMS = [("linux", "amd64"), ("linux", "arm64"), ("darwin", "amd64"), ("darwin", "arm64"), ("windows", "amd64")]


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _member(os_name, arch):
    return "bin/{}_{}/{}".format(os_name, arch, "kubelogin.exe" if os_name == "windows" else "kubelogin")


def _zip(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class FakeResponse:
    def __init__(self, status_code=200, body=b"", headers=None):
        self.status_code = status_code
        self.content = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.headers = headers or {}

    def json(self):
        return json.loads(self.content)

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class FakeRegistry:
    """In-memory registry serving one release zip per platform; requires a bearer token."""

    def __init__(self, tags=("v0.2.21", "v0.2.22"), blob_override=None):
        self.tags = list(tags)
        self.calls = []
        self.blobs, self.manifests, entries = {}, {}, []
        for os_name, arch in PLATFORMS:
            archive = _zip({_member(os_name, arch): "{}-{}-binary".format(os_name, arch)})
            self.blobs[_digest(archive)] = blob_override if blob_override is not None else archive
            manifest = json.dumps({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "layers": [{"mediaType": "application/zip", "digest": _digest(archive), "size": len(archive),
                            "annotations": {"org.opencontainers.image.title": "kubelogin.zip"}}],
            }).encode()
            self.manifests[_digest(manifest)] = manifest
            entries.append({"digest": _digest(manifest), "platform": {"os": os_name, "architecture": arch}})
        self.index = json.dumps({"mediaType": MEDIA_TYPE_OCI_INDEX, "manifests": entries}).encode()

    def get(self, url, headers=None, params=None, **_):
        self.calls.append((url, dict(headers or {}), params))
        if url == "https://registry.example/oauth2/token":
            return FakeResponse(body={"access_token": "anon-token"})
        if (headers or {}).get("Authorization") != "Bearer anon-token":
            return FakeResponse(401, headers={"WWW-Authenticate": CHALLENGE})
        path = url.split("/v2/{}/".format(REPO), 1)[1]
        if path == "tags/list":
            return FakeResponse(body={"name": REPO, "tags": self.tags})
        if path.startswith("manifests/"):
            ref = path[len("manifests/"):]
            if ref in self.tags:
                return FakeResponse(body=self.index)
            if ref in self.manifests:
                return FakeResponse(body=self.manifests[ref])
            return FakeResponse(404)
        if path.startswith("blobs/"):
            return FakeResponse(body=self.blobs[path[len("blobs/"):]])
        return FakeResponse(404)


class TestKubeloginOci(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _client(self, registry):
        session = mock.MagicMock()
        session.get.side_effect = registry.get
        return OciRegistryClient(REGISTRY, REPO, session=session, backoff=0)

    def test_parse_bearer_challenge(self):
        params = parse_bearer_challenge(CHALLENGE)
        self.assertEqual(params["realm"], "https://registry.example/oauth2/token")
        self.assertEqual(params["service"], "registry.example")
        with self.assertRaises(ClientRequestError):
            parse_bearer_challenge('Basic realm="x"')

    def test_anonymous_token_flow(self):
        registry = FakeRegistry()
        self.assertEqual(self._client(registry).list_tags(), ["v0.2.21", "v0.2.22"])
        token_call = [c for c in registry.calls if c[0].endswith("/oauth2/token")]
        self.assertEqual(len(token_call), 1)
        self.assertEqual(token_call[0][2], {"service": "registry.example", "scope": "repository:{}:pull".format(REPO)})
        self.assertEqual(registry.calls[-1][1]["Authorization"], "Bearer anon-token")

    def test_latest_stable_tag(self):
        self.assertEqual(latest_stable_tag(["v0.2.9", "v0.2.22", "v0.2.10", "v0.3.0-rc.1", "latest", "0.9.9"]),
                         "v0.2.22")
        self.assertIsNone(latest_stable_tag(["latest", "v1.0.0-beta"]))
        self.assertEqual(self._client(FakeRegistry(tags=["v0.2.9", "v0.2.10", "v1.0.0-rc.1"])).resolve_latest_version(),
                         "v0.2.10")

    def test_list_tags_follows_pagination(self):
        session = mock.MagicMock()
        session.get.side_effect = [
            FakeResponse(body={"tags": ["v0.2.20"]}, headers={"Link": '</v2/{}/tags/list?last=v0.2.20&n=1>; rel="next"'.format(REPO)}),
            FakeResponse(body={"tags": ["v0.2.21"]}),
        ]
        client = OciRegistryClient(REGISTRY, REPO, session=session, backoff=0)
        self.assertEqual(client.list_tags(), ["v0.2.20", "v0.2.21"])
        self.assertEqual(session.get.call_args_list[1][0][0],
                         "https://registry.example/v2/{}/tags/list?last=v0.2.20&n=1".format(REPO))

    def test_select_platform(self):
        index = json.loads(FakeRegistry().index)
        for os_name, arch in PLATFORMS:
            self.assertEqual(select_platform(index, os_name, arch)["platform"], {"os": os_name, "architecture": arch})
        self.assertIsNone(select_platform(index, "windows", "arm64"))

    def test_get_platform_manifest_and_download(self):
        registry = FakeRegistry()
        client = self._client(registry)
        for os_name, arch in PLATFORMS:
            layer = get_archive_layer(client.get_platform_manifest("v0.2.22", os_name, arch))
            archive = os.path.join(self.temp_dir, "{}-{}.zip".format(os_name, arch))
            client.download_blob(layer, archive)
            binary = os.path.join(self.temp_dir, "{}-{}".format(os_name, arch))
            extract_single_file(archive, _member(os_name, arch), binary)
            with open(binary, "rb") as f:
                self.assertEqual(f.read(), "{}-{}-binary".format(os_name, arch).encode())

    def test_missing_platform(self):
        with self.assertRaisesRegex(ClientRequestError, "not available for platform linux/s390x"):
            self._client(FakeRegistry()).get_platform_manifest("v0.2.22", "linux", "s390x")

    def test_missing_version(self):
        with self.assertRaisesRegex(ClientRequestError, "v9.9.9 was not found"):
            self._client(FakeRegistry()).get_platform_manifest("v9.9.9", "linux", "amd64")

    def test_digest_mismatch(self):
        client = self._client(FakeRegistry(blob_override=b"tampered-archive!"))
        layer = get_archive_layer(client.get_platform_manifest("v0.2.22", "linux", "amd64"))
        layer = dict(layer, size=len(b"tampered-archive!"))
        with self.assertRaisesRegex(ClientRequestError, "Digest mismatch"):
            client.download_blob(layer, os.path.join(self.temp_dir, "kubelogin.zip"))

    def test_size_mismatch(self):
        client = self._client(FakeRegistry(blob_override=b"short"))
        layer = get_archive_layer(client.get_platform_manifest("v0.2.22", "linux", "amd64"))
        with self.assertRaisesRegex(ClientRequestError, "Size mismatch"):
            client.download_blob(layer, os.path.join(self.temp_dir, "kubelogin.zip"))

    def test_unexpected_layer_format(self):
        with self.assertRaises(ClientRequestError):
            get_archive_layer({"layers": [{"mediaType": "application/octet-stream"}]})
        with self.assertRaises(ClientRequestError):
            get_archive_layer({"layers": []})

    def test_extract_single_file_rejects_unexpected_content(self):
        archive = os.path.join(self.temp_dir, "a.zip")
        dest = os.path.join(self.temp_dir, "out")
        cases = [
            {"bin/linux_amd64/kubelogin": "x", "bin/linux_amd64/extra": "y"},
            {"bin/linux_arm64/kubelogin": "x"},
            {},
        ]
        for files in cases:
            with self.subTest(files=list(files)):
                with open(archive, "wb") as f:
                    f.write(_zip(files))
                with self.assertRaisesRegex(ClientRequestError, "Unexpected archive content"):
                    extract_single_file(archive, "bin/linux_amd64/kubelogin", dest)
        with open(archive, "wb") as f:
            f.write(b"not a zip")
        with self.assertRaisesRegex(ClientRequestError, "not a valid zip"):
            extract_single_file(archive, "bin/linux_amd64/kubelogin", dest)

    def test_retries_on_server_error_and_connection_error(self):
        session = mock.MagicMock()
        session.get.side_effect = [FakeResponse(503), requests.ConnectionError("reset"),
                                   FakeResponse(body={"tags": ["v0.2.22"]})]
        client = OciRegistryClient(REGISTRY, REPO, session=session, backoff=0)
        self.assertEqual(client.list_tags(), ["v0.2.22"])
        self.assertEqual(session.get.call_count, 3)

    def test_gives_up_after_retries(self):
        session = mock.MagicMock()
        session.get.return_value = FakeResponse(503)
        client = OciRegistryClient(REGISTRY, REPO, session=session, retries=2, backoff=0)
        with self.assertRaisesRegex(ClientRequestError, "HTTP 503"):
            client.list_tags()
        self.assertEqual(session.get.call_count, 3)

    def test_install_keeps_existing_binary_on_failure(self):
        install_location = os.path.join(self.temp_dir, "kubelogin")
        with open(install_location, "wb") as f:
            f.write(b"old")
        for registry, member in ((FakeRegistry(blob_override=b"tampered-archive!"), _member("linux", "amd64")),
                                 (FakeRegistry(), "bin/linux_amd64/unexpected")):
            with mock.patch("azure.cli.command_modules.acs._kubelogin_oci.requests.Session") as session_cls:
                session_cls.return_value.get.side_effect = registry.get
                with self.assertRaises(ClientRequestError):
                    install_binary_from_registry(REGISTRY, REPO, "v0.2.22", "linux", "amd64", member,
                                                 install_location)
            with open(install_location, "rb") as f:
                self.assertEqual(f.read(), b"old")
            self.assertEqual(os.listdir(self.temp_dir), ["kubelogin"])

    def test_install_latest(self):
        install_location = os.path.join(self.temp_dir, "kubelogin")
        registry = FakeRegistry()
        with mock.patch("azure.cli.command_modules.acs._kubelogin_oci.requests.Session") as session_cls:
            session_cls.return_value.get.side_effect = registry.get
            version = install_binary_from_registry(REGISTRY, REPO, "latest", "darwin", "arm64",
                                                   _member("darwin", "arm64"), install_location)
        self.assertEqual(version, "v0.2.22")
        with open(install_location, "rb") as f:
            self.assertEqual(f.read(), b"darwin-arm64-binary")
        self.assertEqual(os.listdir(self.temp_dir), ["kubelogin"])


class TestInstallKubeloginSource(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.install_location = os.path.join(self.temp_dir, "bin", "kubelogin")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @staticmethod
    def _cmd(cloud_name):
        cmd = mock.MagicMock()
        cmd.cli_ctx.cloud.name = cloud_name
        return cmd

    @mock.patch("azure.cli.command_modules.acs.custom.platform.system", return_value="Linux")
    @mock.patch("azure.cli.command_modules.acs._kubelogin_oci.install_binary_from_registry")
    @mock.patch("azure.cli.command_modules.acs.custom._urlretrieve")
    def test_china_cloud_installs_from_mcr_azure_cn(self, mock_urlretrieve, mock_install, _):
        from azure.cli.command_modules.acs.custom import k8s_install_kubelogin

        def fake_install(registry, repository, version, os_name, arch, member, install_location):
            open(install_location, "w").close()
            return version
        mock_install.side_effect = fake_install
        k8s_install_kubelogin(self._cmd("AzureChinaCloud"), client_version="0.2.22",
                              install_location=self.install_location, arch="arm64")
        mock_install.assert_called_once_with("mcr.azure.cn", "aks/packages/kubernetes/kubelogin", "v0.2.22",
                                             "linux", "arm64", "bin/linux_arm64/kubelogin", self.install_location)
        mock_urlretrieve.assert_not_called()
        self.assertTrue(os.access(self.install_location, os.X_OK))

    @mock.patch("azure.cli.command_modules.acs.custom.platform.system", return_value="Windows")
    @mock.patch("azure.cli.command_modules.acs.custom.handle_windows_post_install")
    @mock.patch("azure.cli.command_modules.acs._kubelogin_oci.install_binary_from_registry")
    def test_china_cloud_windows_uses_windows_amd64(self, mock_install, _, __):
        from azure.cli.command_modules.acs.custom import k8s_install_kubelogin
        mock_install.side_effect = lambda *args: open(args[-1], "w").close()
        location = os.path.join(self.temp_dir, "kubelogin.exe")
        k8s_install_kubelogin(self._cmd("AzureChinaCloud"), client_version="latest", install_location=location,
                              arch="arm64")
        mock_install.assert_called_once_with("mcr.azure.cn", "aks/packages/kubernetes/kubelogin", "latest",
                                             "windows", "amd64", "bin/windows_amd64/kubelogin.exe", location)

    @mock.patch("azure.cli.command_modules.acs.custom.platform.system", return_value="Linux")
    @mock.patch("azure.cli.command_modules.acs._kubelogin_oci.install_binary_from_registry")
    def test_china_cloud_registry_failure_is_not_silently_replaced(self, mock_install, _):
        from azure.cli.command_modules.acs.custom import k8s_install_kubelogin
        mock_install.side_effect = ClientRequestError("Digest mismatch")
        with self.assertRaisesRegex(ClientRequestError, "mcr.azure.cn/aks/packages/kubernetes/kubelogin"):
            k8s_install_kubelogin(self._cmd("AzureChinaCloud"), client_version="0.2.22",
                                  install_location=self.install_location, arch="amd64")
        self.assertFalse(os.path.exists(self.install_location))

    @mock.patch("azure.cli.command_modules.acs._kubelogin_oci.install_binary_from_registry")
    @mock.patch("azure.cli.command_modules.acs.custom._urlretrieve")
    def test_china_cloud_explicit_source_url_uses_zip(self, mock_urlretrieve, mock_install):
        from azure.cli.command_modules.acs.custom import k8s_install_kubelogin
        from azure.cli.command_modules.acs.tests.latest.utils import create_kubelogin_zip
        mock_urlretrieve.side_effect = create_kubelogin_zip
        location = os.path.join(self.temp_dir, "kubelogin.exe" if os.name == "nt" else "kubelogin")
        k8s_install_kubelogin(self._cmd("AzureChinaCloud"), client_version="0.2.22", install_location=location,
                              source_url="https://example.com/kubelogin", arch="amd64")
        mock_install.assert_not_called()
        self.assertEqual(mock_urlretrieve.call_args[0][0], "https://example.com/kubelogin/v0.2.22/kubelogin.zip")
        self.assertTrue(os.path.exists(location))

    @mock.patch("azure.cli.command_modules.acs._kubelogin_oci.install_binary_from_registry")
    @mock.patch("azure.cli.command_modules.acs.custom._urlretrieve")
    def test_public_cloud_still_uses_github(self, mock_urlretrieve, mock_install):
        from azure.cli.command_modules.acs.custom import k8s_install_kubelogin
        from azure.cli.command_modules.acs.tests.latest.utils import create_kubelogin_zip
        mock_urlretrieve.side_effect = create_kubelogin_zip
        location = os.path.join(self.temp_dir, "kubelogin.exe" if os.name == "nt" else "kubelogin")
        k8s_install_kubelogin(self._cmd("AzureCloud"), client_version="0.2.22", install_location=location,
                              arch="amd64")
        mock_install.assert_not_called()
        self.assertEqual(mock_urlretrieve.call_args[0][0],
                         "https://github.com/Azure/kubelogin/releases/download/v0.2.22/kubelogin.zip")


if __name__ == "__main__":
    unittest.main()
