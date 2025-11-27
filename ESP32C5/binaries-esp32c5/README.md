## esptool & pyserial requirement

Flashing the ESP32-C5 requires the Python packages `esptool` (v5 or newer) and `pyserial`. The flasher script (`flash_board.py`) will attempt to auto-install missing packages, but pre-installing them avoids UAC/prompt issues.

Check installed packages (platform-specific):

- Windows (CMD):
```bash
pip list | findstr esptool pyserial
```
- Windows (PowerShell):
```powershell
pip list | Select-String -Pattern "esptool|pyserial"
```
- macOS / Linux:
```bash
pip list | grep -E "esptool|pyserial"
```
- Cross-platform (recommended):
```bash
python -m pip show esptool pyserial
```
The `python -m pip show <pkg>` command prints a `Version:` line so you can confirm versions.

Install / update the required packages (cross-platform):
```bash
python -m pip install --upgrade esptool pyserial
```
Or using pip directly:
```bash
pip install --upgrade esptool pyserial
```

Optional: ensure you have a recent Python 3 installation and pip available. The flasher uses `python -m pip` to install/check packages when needed.