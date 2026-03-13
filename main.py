import argparse
import pathlib
import os
import time
import json
import requests
from base64 import b64encode
from collections import defaultdict
from datetime import datetime
from hashlib import sha1, sha256
from zipfile import ZipFile

import xxhash
from tqdm import tqdm
from pyjarsigner.manifest import Manifest, SignatureManifest
from pyjarsigner.crypto import private_key_type

javatime = lambda: int(time.time() * 1000)
timestr_to_timestamp = lambda timestr: int(datetime.fromisoformat(timestr).timestamp() * 1000)

def get_indexv1_json_path(args):
    return os.path.join(args.repo, "index-v1.json")

def save_indexv1(args, index_v1):
    with open(get_indexv1_json_path(args), "w") as f:
        index_v1["repo"]["timestamp"] = javatime()
        index_v1["repo"]["version"] += 1
        json.dump(index_v1, f, ensure_ascii=False)

def load_indexv1(args):
    with open(get_indexv1_json_path(args), "r") as f:
        index_v1 = json.load(f)
        index_v1["packages"] = defaultdict(list, index_v1["packages"])
        return index_v1

def indexv1_get_app_idx(indexv1, package_id) -> int:
    for i, app in enumerate(indexv1["apps"]):
        if app["packageName"] == package_id:
            return i
    return -1

def indexv1_package_contains_version(indexv1, package_id, version_code) -> bool:
    for package in indexv1["packages"][package_id]:
        if package["versionCode"] == version_code:
            return True
    return False

def download_and_get_sha256(args, url, output, size = None):
    bar = tqdm(total = size, desc = f"Downloading {os.path.basename(output)}",
               unit="B", unit_scale=True)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    chunk_size = args.download_chunk_size
    with requests.get(url, stream=True) as r:
        with open(output, "wb") as f:
            hash_context = sha256()
            for iter_ in r.iter_content(chunk_size):
                f.write(iter_)
                hash_context.update(iter_)
                bar.update(len(iter_))
            bar.close()
            return output, hash_context.hexdigest()


def command_init(args):
    index_v1 = {
        "repo" : {
            "timestamp": javatime(),
            "version": 1,
            "name": args.name,
            "icon": "icon.jpg",
            "address": args.address,
            "description": args.description,
        },
        "requests": {
            "install": [],
            "uninstall": [],
        },
        "apps": [],
        "packages": {},
    }

    save_indexv1(args, index_v1)

    print(f"New empty repository initialized at {args.repo}!")

def command_add(args):
    index_v1 = load_indexv1(args)

    info = requests.get(f"https://backapi.rustore.ru/applicationData/overallInfo/{args.package_id}").json()["body"]
    app_id = info["appId"]
    dl_info = requests.post("https://backapi.rustore.ru/applicationData/v2/download-link", json={"appId": app_id}).json()["body"]

    package_name = info["packageName"]
    version_code = info["versionCode"]

    icon_file, icon_hash = download_and_get_sha256(args, info["iconUrl"],
                                                os.path.join(args.repo, "icons", f"{package_name}.icon.jpg"))

    app_idx = indexv1_get_app_idx(index_v1, package_name)
    if app_idx == -1:
        index_v1["apps"].append({
            "packageName": package_name,
            "added": timestr_to_timestamp(info["firstPublishedAt"]),
            "icon": os.path.basename(icon_file),
            "license": "Unknown",
            "antiFeatures": [
                "NoSourceSince"
            ],
        })

    # i know app_idx could be -1, i just abuse this behaviour
    index_v1["apps"][app_idx]["name"] = info["appName"]
    index_v1["apps"][app_idx]["summary"] = info["shortDescription"]
    index_v1["apps"][app_idx]["description"] = info["fullDescription"]
    index_v1["apps"][app_idx]["allowedAPKSigningKeys"] = info["signatures"]
    index_v1["apps"][app_idx]["authorName"] = info["companyName"]
    index_v1["apps"][app_idx]["categories"] = info["categories"]

    index_v1["apps"][app_idx]["suggestedVersionName"] = info["versionName"]
    index_v1["apps"][app_idx]["suggestedVersionCode"] = str(info["versionCode"])
    index_v1["apps"][app_idx]["lastUpdated"] = timestr_to_timestamp(info["appVerUpdatedAt"])

    if not indexv1_package_contains_version(index_v1, package_name, version_code):
        apk_download_url = dl_info["downloadUrls"][0]
        apk_file = os.path.join(args.repo, f"{package_name}_{version_code}.apk")

        # TODO: find a way to get "uses-permission" because fdroid shows a warning
        index_package = {
            "packageName": package_name,
            "added": timestr_to_timestamp(info["appVerUpdatedAt"]),
            "size": apk_download_url["size"],
            "apkName": os.path.basename(apk_file),
            "hashType": "sha256",
            "sig": "deadbeef", # FIXME: impl 'sig'
            "signer": dl_info["signature"],
            "minSdkVersion": info["minSdkVersion"],
            "targetSdkVersion": info["targetSdkVersion"],
            "versionCode": version_code,
            "versionName": info["versionName"],
        }

        if os.path.exists(apk_file) and xxhash.xxh64(open(apk_file, "rb").read()).hexdigest() == apk_download_url["hash"]:
            index_package["hash"] = sha256(open(apk_file, "rb").read()).hexdigest()
        else:
            _, apk_hash = download_and_get_sha256(args,
                apk_download_url["url"],
                os.path.join(args.repo, f"{package_name}_{version_code}.apk"),
                size = apk_download_url["size"],
            )
            index_package["hash"] = apk_hash

        index_v1["packages"][package_name].append(index_package)

    save_indexv1(args, index_v1)

def command_remove(args):
    index_v1 = load_indexv1(args)
    idx = indexv1_get_app_idx(index_v1, args.package_id)
    if idx == -1:
        print(f"Application {args.package_id} is not in repository!")
        return

    app = index_v1["apps"][idx]
    if not args.keep_files:
        try:
            os.remove(os.path.join(args.repo, "icons", app["icon"]))
        except FileNotFoundError:
            pass
        for package in index_v1["packages"][app["packageName"]]:
            try:
                os.remove(os.path.join(args.repo, package["apkName"]))
            except FileNotFoundError:
                pass

    del index_v1["packages"][app["packageName"]]
    del index_v1["apps"][idx]

    save_indexv1(args, index_v1)


def command_list(args):
    index_v1 = load_indexv1(args)
    for app in index_v1["apps"]:
        print(app["packageName"], "|", app["name"])

def command_sign(args):
    with open(get_indexv1_json_path(args), "r") as f:
        index_v1 = f.read()

    manifest = Manifest()
    section = manifest.create_section("index-v1.json")
    section["SHA1-Digest"] = b64encode(sha1(index_v1.encode()).digest()).decode()

    signature_manifest = SignatureManifest()
    signature_manifest.digest_manifest(manifest, java_algorithm = "SHA1")

    sigdata = signature_manifest.get_signature(args.cert, args.key,
                                            extra_certs = None, digest_algorithm = "SHA1")

    with ZipFile(os.path.join(args.repo, "index-v1.jar"), "w") as jar:
        jar.writestr("META-INF/", "")
        jar.writestr("META-INF/MANIFEST.MF", manifest.get_data())
        jar.writestr("META-INF/CERT.SF", signature_manifest.get_data())
        jar.writestr("META-INF/CERT." + private_key_type(args.key), sigdata)
        jar.writestr("index-v1.json", index_v1)

def parse_args():
    parser = argparse.ArgumentParser(description="rustore-fdroid-bridge repo manager")
    parser.add_argument("-r", "--repo", type=pathlib.Path, required = True, help = "Repository path")
    parser.add_argument("--download_chunk_size", type=int, default = 1024 * 128, help = "Chunk size for file downloader")

    parser_subcommands = parser.add_subparsers(required=True)

    # TODO: add "update" subcommand

    parser_init = parser_subcommands.add_parser("init", description="Initialize empty repository")
    parser_init.set_defaults(callback = command_init)
    parser_init.add_argument("-n", "--name", required = True)
    parser_init.add_argument("-d", "--description", required = True)
    parser_init.add_argument("-a", "--address", required = True)

    parser_add = parser_subcommands.add_parser("add", description="Add app from rustore")
    parser_add.set_defaults(callback = command_add)
    parser_add.add_argument("package_id")

    parser_remove = parser_subcommands.add_parser("remove", description="Remove app from repository")
    parser_remove.set_defaults(callback = command_remove)
    parser_remove.add_argument("package_id")
    parser_remove.add_argument("-k", "--keep-files", action="store_true", default = False,
                               help = "Keep icon and apk files of application")

    parser_list = parser_subcommands.add_parser("list", description="Get list of packages in repository")
    parser_list.set_defaults(callback = command_list)

    parser_sign = parser_subcommands.add_parser("sign", description="Sign repository(generates index-v1.jar)")
    parser_sign.set_defaults(callback = command_sign)
    parser_sign.add_argument("-k", "--key", required = True, type=pathlib.Path)
    parser_sign.add_argument("-c", "--cert", required = True, type=pathlib.Path)

    return parser.parse_args()

def main():
    args = parse_args()
    if not args.repo.exists():
        args.repo.mkdir()
    args.callback(args)

if __name__ == "__main__":
    main()
