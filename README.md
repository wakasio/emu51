# emu51

A small 8051 interpreter (`emu51.py`) and disassembler (`disasm8051.py`) in plain Python 3, no
dependencies. I use them to check firmware patches for MediaTek-based optical drives: run a
routine from the stock image and from the patched image over many inputs and compare what each
one writes to IRAM/XDATA and the registers.

- `emu51.CPU(img, code_map=...)` takes the flash image and a function mapping a 16-bit code
  address to a file offset, so banked images work: `eh33_map(bank)` for the Lite-On EH33 /
  DH-16D2S layout, `common64_map(bank)` for 64 KiB banks with a repeated common area (VAD6038).
- `cpu.call(addr)` runs a routine until it returns. XDATA is a dict (`cpu.x`); hardware
  registers are modelled with chained read/write hooks (`add_xr_hook`, `add_xw_hook`).
- SP starts at 0x07 (8051 reset). Real firmware moves it (EH33 0x9D, VAD6038 0x9B): pass
  `sp=` when running firmware code. All SFRs, ports included, start at 0.
- `Divider` is a partial, inferred model of the arithmetic unit at 0x403B (only the /75 and /60
  commands used for LBA to MSF).
- Not modelled: interrupts, timers, ports (bank switching through P1 only via your code map),
  timing.

`python3 disasm8051.py <file> <start_hex> <len_hex> [base_hex]` prints a listing.
