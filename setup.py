# setup.py
from cx_Freeze import setup, Executable

# the list of every sub-module you discovered you need:
includes = [
    "pymupdf",
    "OpenSSL",           
    "OpenSSL.crypto",
    "qtpy",
    "PyQt5.QtCore",
    "PyQt5.QtGui",
    "PyQt5.QtWidgets",
    "PyQt6.QtCore",
    "PyQt6.QtGui",
    "PyQt6.QtWidgets",
    "_curses",
    "aiodns",
    "async_timeout",
    "brotli",
    "brotlicffi",
    "collections.abc",
    "cryptography",
    "cryptography.x509",
    "cryptography.x509.extensions",
    "gunicorn.config",
    "gunicorn.workers",
    "h2.config",
    "h2.connection",
    "h2.events",
    "html5lib",
    "html5lib.constants",
    "html5lib.treebuilders",
    "js2py",
    "numpy.distutils",
    "numpy.random.RandomState",
    "orjson",
    "simplejson",
    "pysocks",
    "uvloop",
    "zstandard.backend_rust",
]

build_exe_options = {
    "includes": [
        # any modules you explicitly need
    ],
    "packages": [
        "collections",
    ],
    "excludes": [
       
    ],
}


exe = Executable(
    script="SARA2.8.py",
    base="console",
    target_name="SARA2.8.exe",
)

setup(
    name="SARA2.8",
    version="0.1",
    description="",
    options={ "build_exe": build_exe_options },
    executables=[exe],
)

