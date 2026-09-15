#!/usr/bin/env python3
"""Validate the checked-in OpenBao stable UI parity ownership manifest."""

from pathlib import Path
from runpy import run_path


def main() -> None:
    module = run_path(Path(__file__).parents[1] / "netbox_openbao" / "administration" / "parity.py")
    manifest = module["load_parity_manifest"]()
    print(
        f"OpenBao UI parity manifest {manifest['baseline']}: "
        f"{len(manifest['families'])} capability families valid; complete families are evidence-backed"
    )


if __name__ == "__main__":
    main()
