# Copyright 2021 Gabriel Adrian Samfira
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import requests
import platform
import os
import base45
import cwt
import cbor
import zlib
import cbor_json
import json
import datetime


_AUSTRIAN_NATIONAL_BACKEND = "https://dgc-trust.qr.gv.at"
_TRUSTLIST = "%s/trustlist" % _AUSTRIAN_NATIONAL_BACKEND
_EPOCH = datetime.datetime.strptime(
    "Mon, 01 Jan 1900 00:00:00 UTC", "%a, %d %b %Y %H:%M:%S %Z")

def get_app_dir():
    system = platform.system()
    if system == "Linux":
        home = os.environ.get("HOME", "/tmp")
        return os.path.join(home, ".local", "share", "verify_dgc")
    elif system == "Windows":
        home = os.environ.get("APPDATA", "C:\\Windows\\temp")
        return os.path.join(home, "verify_dgc")
    raise Exception("Unknown system type %s" % system)


class Verify(object):

    def __init__(self, appdata):
        self._appdata = appdata
        self._metadata_file = os.path.join(
            self._appdata, "metadata.json")
        self._cert_store = os.path.join(
            self._appdata, "cert_store.json")
        if os.path.isdir(self._appdata) is False:
            os.makedirs(self._appdata)

    def _load_local_cache(self):
        cache_location = os.path.join(self._appdata, "cache.json")
        data = {}
        if os.path.isfile(cache_location):
            with open(cache_location, "rb") as fd:
                try:
                    data = json.load(fd)
                except Exception as err:
                    # should use logging module
                    print("Failed to load cache data: %s" % err)
                    os.remove(cache_location)
        return data

    def _current_version(self):
        data = requests.head(_TRUSTLIST)
        last_modified = data.headers.get("Last-Modified", None)
        if last_modified is None:
            return datetime.datetime.utcnow()
        return datetime.datetime.strptime(
            last_modified, "%a, %d %b %Y %H:%M:%S %Z")

    @property
    def should_refresh(self):
        current_version = self._current_version()
        cache = self._load_local_cache()
        last_modified = cache.get(
                "last_modified",
                0)
        max_age = cache.get("max_age", 31536000)
        as_datetime = datetime.datetime.fromtimestamp(last_modified)

        print(as_datetime, current_version)
        if as_datetime != current_version:
            return True

        now = datetime.datetime.utcnow()
        max_aged = as_datetime + datetime.timedelta(seconds=max_age)
        print(now, max_aged)
        if now > max_aged:
            return True
        return False

    def _update_metadata_from_headers(self, headers):
        last_modified = headers.get("Last-Modified", None)
        strict_transport_sec = headers.get(
            "Strict-Transport-Security", None)

        timestamp = datetime.datetime.utcnow().strftime("%s")
        if last_modified:
            timestamp = datetime.datetime.strptime(
                last_modified, "%a, %d %b %Y %H:%M:%S %Z").timestamp()

        max_age = 315360
        if strict_transport_sec:
            fields = strict_transport_sec.split(';')
            for field in fields:
                if field.strip().startswith("max-age="):
                    max_age = int(field.strip()[8:])
        with open(self._metadata_file, "w") as fd:
            json.dump({
                "last_modified": timestamp,
                "max_age": max_age,
                }, fd)

    def refresh_cert_store(self):
        print("refreshing cert store")
        if self.should_refresh is False:
            print("cert store is up to date")
            return
        
        data = requests.get(_TRUSTLIST)
        data.raise_for_status()
        with open(self._cert_store, "w") as fd:
            as_jsonable = cbor_json.jsonable_from_cbor(
                data.content)
            json.dump(as_jsonable, fd)
        self._update_metadata_from_headers(data.headers)

    def _load_cert_store(self):
        data = {"c": []}
        if os.path.isfile(self._cert_store):
            with open(self._cert_store, 'rb') as fd:
                data = json.load(fd)
        return data 

    def _convert_store_cert_to_hcert(self, crt):
        h = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % (
            crt)
        return cwt.load_pem_hcert_dsc(h)

    def _assemble_certs(self):
        cert_data = self._load_cert_store()
        cert_store = []
        for cert in cert_data["c"]:
            crt = self._convert_store_cert_to_hcert(
                cert["c"]["$value"])
            cert_store.append(crt)
        return cert_store

    def verify(self, data):
        cert_store = self._assemble_certs()
        return self.verify_with_cert_store(
            data, cert_store)

    def verify_with_cert_store(self, data, cert_store):
        if data.startswith("HC1:"):
            # qr code data
            encoded = data[4:]
            as_binary = base45.b45decode(encoded)
            data = zlib.decompress(as_binary)
        decoded = cwt.decode(data, keys=cert_store)
        return decoded


if __name__ == "__main__":
    appdir = get_app_dir()
    v = Verify(appdir)
    v.refresh_cert_store()
    # Add the QR code data here, or the raw dgc data
    data = "HC1:......"
    print(v.verify(data))
