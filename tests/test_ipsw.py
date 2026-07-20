import plistlib
import zipfile

from ttg_device_xray.analyzers.ipsw import IpswAnalyzer


def test_ipsw_manifest_analysis(tmp_path):
    path = tmp_path / "sample.ipsw"
    manifest = {
        "ProductVersion": "18.5",
        "ProductBuildVersion": "22F76",
        "SupportedProductTypes": ["iPhone10,6"],
        "BuildIdentities": [
            {
                "ApChipID": 0x8015,
                "ApBoardID": 0x0E,
                "Info": {
                    "ProductType": "iPhone10,6",
                    "DeviceClass": "d221ap",
                    "RestoreBehavior": "Erase",
                    "Variant": "Customer Erase Install",
                },
                "Manifest": {
                    "iBSS": {"Info": {"Path": "Firmware/dfu/iBSS.im4p"}},
                },
            }
        ],
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("BuildManifest.plist", plistlib.dumps(manifest))
    report = IpswAnalyzer(path).analyze()
    assert report["product_version"] == "18.5"
    assert report["supported_product_types"] == ["iPhone10,6"]
    assert report["board_configs"] == ["d221ap"]
    assert report["build_identity_count"] == 1
