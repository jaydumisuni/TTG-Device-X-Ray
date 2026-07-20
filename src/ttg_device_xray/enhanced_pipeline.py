from __future__ import annotations

from .models import DeviceIdentity, TransportKind, TransportObservation
from .pipeline import XRayPipeline


class EnhancedXRayPipeline(XRayPipeline):
    """Pipeline extensions for service-mode transports.

    Core X-Ray remains transport-neutral. This subclass teaches correlation how
    to consume MTK META evidence without pretending that META is ADB.
    """

    @staticmethod
    def _correlate(observations: list[TransportObservation]) -> DeviceIdentity:
        identity = XRayPipeline._correlate(observations)
        for observation in observations:
            if not observation.connected or observation.transport != TransportKind.MTK_META:
                continue
            ids = observation.identifiers
            identity.platform = "android"
            identity.active_mode = observation.mode
            identity.evidence_sources.append(observation.transport.value)
            identity.brand = ids.get("brand", ids.get("manufacturer", identity.brand))
            identity.manufacturer = ids.get("manufacturer", identity.manufacturer)
            identity.marketing_model = ids.get(
                "marketing_model", ids.get("model_name", identity.marketing_model)
            )
            identity.internal_model = ids.get(
                "device",
                ids.get("model_code", ids.get("model", identity.internal_model)),
            )
            identity.product_name = ids.get("product", identity.product_name)
            identity.board = ids.get(
                "board", ids.get("platform", ids.get("target", identity.board))
            )
            identity.chipset = ids.get(
                "chipset",
                ids.get("soc", ids.get("platform", ids.get("target", identity.chipset))),
            )
            identity.serial = ids.get("serial", identity.serial)
            identity.imei = ids.get("imei", identity.imei)
            identity.firmware_version = ids.get(
                "android", ids.get("android_version", identity.firmware_version)
            )
            identity.build = ids.get(
                "build", ids.get("build_id", ids.get("software_version", identity.build))
            )
            identity.build_fingerprint = ids.get(
                "fingerprint", ids.get("build_fingerprint", identity.build_fingerprint)
            )
            identity.security_patch = ids.get(
                "security_patch", identity.security_patch
            )
            identity.baseband = ids.get(
                "baseband", ids.get("modem_version", identity.baseband)
            )
            identity.bootloader = ids.get(
                "bootloader", ids.get("preloader_version", identity.bootloader)
            )
            identity.storage_type = ids.get("storage_type", identity.storage_type)
            identity.storage_model = ids.get("storage_model", identity.storage_model)
            capacity = ids.get("storage_capacity_bytes", "")
            if str(capacity).isdigit():
                identity.storage_capacity_bytes = int(capacity)
            storage = observation.capabilities.get("storage")
            if isinstance(storage, dict):
                identity.storage_type = str(storage.get("type", identity.storage_type))
                identity.storage_model = str(storage.get("model", identity.storage_model))
                try:
                    identity.storage_capacity_bytes = int(
                        storage.get("capacity_bytes", identity.storage_capacity_bytes) or 0
                    )
                except (TypeError, ValueError):
                    pass

        identity.evidence_sources = sorted(set(identity.evidence_sources))
        return identity
