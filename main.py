import requests
import sys
import time
import json
import os

from base64 import b64encode
from collections import defaultdict
from datetime import datetime
from hashlib import sha1, sha256
from zipfile import ZipFile

from pyjarsigner.manifest import Manifest, SignatureManifest
from pyjarsigner.crypto import private_key_type
from tqdm import tqdm
import xxhash
import yaml

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <config.yml>")
    sys.exit(-1)

config = yaml.safe_load(open(sys.argv[1]))

# TODO: add support for re-using existing index-v1.json
index_v1 = {
    "repo" : {
        "timestamp": int(time.time() * 1000),
        "version": config["version"], # TODO: increase it after updating/adding new app
        "name": config["name"],
        "icon": config["icon"],
        "address": config["address"],
        "description": config["description"],
    },
    "requests": {
        "install": [],
        "uninstall": [],
    },
    "apps": [],
    "packages": defaultdict(list)
}

repo_path = config["repo_path"]

timestr_to_timestamp = lambda timestr: int(datetime.fromisoformat(timestr).timestamp() * 1000)

chunk_size = config["download_chunk_size"]

def download_and_get_sha256(url, output, size = None):
    bar = tqdm(total = size, desc = f"Downloading {os.path.basename(output)}",
               unit="B", unit_scale=True)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with requests.get(url, stream=True) as r:
        with open(output, "wb") as f:
            hash_context = sha256()
            for iter_ in r.iter_content(chunk_size):
                f.write(iter_)
                hash_context.update(iter_)
                bar.update(chunk_size)
            bar.close()
            return output, hash_context.hexdigest()

def add_app(package):
    info = requests.get(f"https://backapi.rustore.ru/applicationData/overallInfo/{package}").json()["body"]
    app_id = info["appId"]
    download_link_info = requests.post("https://backapi.rustore.ru/applicationData/v2/download-link", json={"appId": app_id}).json()["body"]

    package_name = info["packageName"]
    version_code = info["versionCode"]

    icon_file, icon_hash = download_and_get_sha256(info["iconUrl"], os.path.join(repo_path, "icons", f"{package_name}.icon.jpg"))

    index_v1["apps"].append({
        "packageName": package_name,
        "name": info["appName"],
        "summary": info["shortDescription"],
        "description": info["fullDescription"],
        "allowedAPKSigningKeys": info["signatures"],
        "authorName": info["companyName"],
        "categories": info["categories"],
        "suggestedVersionName": info["versionName"],
        "suggestedVersionCode": str(version_code),
        "added": timestr_to_timestamp(info["firstPublishedAt"]),
        "lastUpdated": timestr_to_timestamp(info["appVerUpdatedAt"]),
        "icon": os.path.basename(icon_file), # TODO: cut only "icons/" part
        "license": "Unknown",
        "antiFeatures": [
            "NoSourceSince"
        ],
    })

    apk_download_url = download_link_info["downloadUrls"][0]
    apk_file = os.path.join(repo_path, f"{package_name}_{version_code}.apk")

    # TODO: find a way to get "uses-permission" because fdroid shows a warning
    index_package = {
        "packageName": package_name,
        "added": timestr_to_timestamp(info["appVerUpdatedAt"]),
        "size": apk_download_url["size"],
        "apkName": os.path.basename(apk_file),
        "hashType": "sha256",
        "sig": "deadbeef", # FIXME: impl 'sig'
        "signer": download_link_info["signature"],
        "minSdkVersion": info["minSdkVersion"],
        "targetSdkVersion": info["targetSdkVersion"],
        "versionCode": version_code,
        "versionName": info["versionName"],
    }

    if os.path.exists(apk_file) and xxhash.xxh64(open(apk_file, "rb").read()).hexdigest() == apk_download_url["hash"]:
        index_package["hash"] = sha256(open(apk_file, "rb").read()).hexdigest()
    else:
        _, apk_hash = download_and_get_sha256(
            apk_download_url["url"],
            os.path.join(repo_path, f"{package_name}_{version_code}.apk"),
            size = apk_download_url["size"],
        )
        index_package["hash"] = apk_hash

    index_v1["packages"][package_name].append(index_package)

os.makedirs(repo_path, exist_ok=True)

apps_count = len(config["apps"])
for idx, app in enumerate(config["apps"]):
    print(f"Downloading {app} | {idx + 1}/{apps_count}")
    add_app(app)

json.dump(index_v1, open(os.path.join(repo_path, "index-v1.json"), "w"), ensure_ascii = False)

# Generate index-v1.jar
index_v1_json = json.dumps(index_v1)

manifest = Manifest()
section = manifest.create_section("index-v1.json")
section["SHA1-Digest"] = b64encode(sha1(index_v1_json.encode()).digest()).decode()

signature_manifest = SignatureManifest(linesep=manifest.linesep)
signature_manifest.digest_manifest(manifest, java_algorithm = "SHA1")

sigdata = signature_manifest.get_signature(config["signing"]["cert"], config["signing"]["key"],
                                           extra_certs = None, digest_algorithm = "SHA1")

with ZipFile(os.path.join(repo_path, "index-v1.jar"), "w") as jar:
    jar.writestr("META-INF/", "")
    jar.writestr("META-INF/MANIFEST.MF", manifest.get_data())
    jar.writestr("META-INF/CERT.SF", signature_manifest.get_data())
    jar.writestr("META-INF/CERT." + private_key_type(config["signing"]["key"]), sigdata)
    jar.writestr("index-v1.json", index_v1_json)
