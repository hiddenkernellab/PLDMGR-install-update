#!/usr/bin/env python3

import sys
from pathlib import Path


def main():
    if len(sys.argv) != 4:
        raise SystemExit(
            "Uso: gen_asset.py INPUT OUTPUT SYMBOL"
        )

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    symbol = sys.argv[3]

    data = input_path.read_bytes()

    lines = []

    for index in range(0, len(data), 12):
        chunk = data[index:index + 12]

        line = ", ".join(
            f"0x{byte:02x}"
            for byte in chunk
        )

        lines.append(
            "    " + line + ","
        )

    output = (
        "#pragma once\n\n"
        f"static const unsigned char {symbol}[] = {{\n"
        + "\n".join(lines)
        + "\n};\n\n"
        f"static const unsigned int {symbol}_len = {len(data)};\n"
    )

    output_path.write_text(
        output,
        encoding="utf-8"
    )


if __name__ == "__main__":
    main()
