"""Media profiles, NIST SP 800-88 Rev. 2 method catalogue, and media-specific guidance.

NIST SP 800-88 Rev. 2 (Sept 2025) keeps the Clear / Purge / Destroy categories and points to
IEEE 2883-2022 for media-specific techniques. Overwriting is a *Clear* technique; on flash media
(SSD, NVMe, USB, SD) it is unreliable because of wear-levelling, over-provisioned spare blocks and
remapped bad blocks the host cannot address. Those need a *Purge* technique executed by the
device firmware: ATA SANITIZE / SECURITY ERASE, NVMe Sanitize (block erase / crypto erase) or a
cryptographic erase of a self-encrypting drive.
"""
from __future__ import annotations

from dataclasses import dataclass

PROFILES = {
    "HDD": "Magnetic hard disk (ATA/SATA/SAS)",
    "SSD": "SATA solid-state drive",
    "NVMe": "NVMe solid-state drive",
    "USB": "USB flash drive / memory card",
    "image": "Disk image file",
}


@dataclass(frozen=True)
class Method:
    id: str
    label: str
    category: str          # Clear | Purge
    technique: str         # overwrite | ata-secure-erase | nvme-sanitize-block | nvme-sanitize-crypto | crypto-erase
    passes: tuple[str, ...] = ()
    description: str = ""


METHODS: dict[str, Method] = {m.id: m for m in [
    Method("clear-zero", "Single-pass zero overwrite", "Clear", "overwrite", ("zero",),
           "Overwrite all user-addressable locations with 0x00, then read back to verify."),
    Method("clear-random", "Single-pass random overwrite", "Clear", "overwrite", ("random",),
           "Overwrite with a cryptographic (ChaCha20) pseudo-random stream; verification regenerates it."),
    Method("clear-multipass", "Multi-pass overwrite + verification", "Clear", "overwrite",
           ("random", "ones", "zero"),
           "Three passes (random, 0xFF, 0x00), each verified by read-back. Extra passes add assurance "
           "against write failures; NIST notes a single verified pass is sufficient for Clear on HDDs."),
    Method("purge-ata-secure-erase", "ATA Secure Erase (Enhanced)", "Purge", "ata-secure-erase", (),
           "Firmware erases all user data areas including remapped sectors (hdparm --security-erase-enhanced)."),
    Method("purge-nvme-sanitize-block", "NVMe Sanitize - Block Erase", "Purge", "nvme-sanitize-block", (),
           "Controller erases every NAND block incl. over-provisioned area (nvme sanitize --sanact=2)."),
    Method("purge-nvme-sanitize-crypto", "NVMe Sanitize - Crypto Erase", "Purge", "nvme-sanitize-crypto", (),
           "Controller changes the media encryption key (nvme sanitize --sanact=4)."),
    Method("purge-crypto-erase", "Cryptographic Erase", "Purge", "crypto-erase", (),
           "Destroy the media encryption key of a self-encrypting drive; all data becomes ciphertext "
           "under an unrecoverable key."),
]}

APPLICABLE = {
    "HDD": ["clear-zero", "clear-random", "clear-multipass", "purge-ata-secure-erase"],
    "SSD": ["clear-zero", "clear-random", "purge-ata-secure-erase", "purge-crypto-erase"],
    "NVMe": ["clear-zero", "clear-random", "purge-nvme-sanitize-block", "purge-nvme-sanitize-crypto",
             "purge-crypto-erase"],
    "USB": ["clear-zero", "clear-random", "clear-multipass"],
    "image": list(METHODS),
}

FLASH = {"SSD", "NVMe", "USB"}


def guidance(profile: str) -> list[str]:
    g = []
    if profile in FLASH:
        g.append("Flash media: overwriting cannot reach wear-levelled, over-provisioned or remapped blocks, "
                 "so an overwrite is at best a Clear. Use a firmware Purge command (or Destroy) for "
                 "media leaving your control.")
    if profile == "USB":
        g.append("Most USB flash drives and SD cards expose no Purge command. NIST guidance: Clear by "
                 "overwrite for reuse inside the organisation; Destroy (shred/disintegrate) otherwise.")
    if profile == "HDD":
        g.append("Magnetic HDD: a single verified overwrite pass satisfies Clear. ATA Secure Erase "
                 "(Purge) also covers sectors the drive has remapped.")
    if profile == "image":
        g.append("Disk image: overwrites are real. Firmware Purge commands are simulated with "
                 "equivalent end states, and the certificate records that they were simulated.")
    return g


def method_warning(method_id: str, profile: str) -> str | None:
    m = METHODS[method_id]
    if m.technique == "overwrite" and profile in FLASH:
        return ("Warning: overwriting flash media is unreliable (wear-levelling / over-provisioning). "
                "The certificate will record NIST category 'Clear' only.")
    if method_id not in APPLICABLE.get(profile, []):
        return f"{m.label} is not applicable to {PROFILES.get(profile, profile)} media."
    return None
