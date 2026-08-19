# -*- mode: python ; coding: utf-8 -*-
"""
minisiem.spec
-------------
PyInstaller build definition for the Mini SIEM desktop executable.

Build with:
    pyinstaller minisiem.spec --noconfirm

A .spec file is used rather than a long one-line pyinstaller command
because three things here are easy to get wrong and painful to debug:

  datas         Templates, static assets and the sigma rule YAMLs are
                loaded at runtime by filename. PyInstaller only follows
                Python imports, so it has no idea these files exist and
                would silently ship an exe that 500s on every page.

  hiddenimports Modules reached through dynamic import rather than a
                plain `import x` statement. pywin32's win32evtlog family
                is imported inside a try/except at runtime, and the
                detection engine resolves rule modules by name, so the
                static analyser misses both.

  console       Kept True on purpose. The window streams live detections
                and startup diagnostics; a windowed build would hide the
                one thing that tells you the app is working.
"""

block_cipher = None


a = Analysis(
    ['launcher.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('static', 'static'),
        ('sigma_rules', 'sigma_rules'),
    ],
    hiddenimports=[
        # pywin32 - imported lazily for Windows Event Log collection
        'win32evtlog',
        'win32evtlogutil',
        'win32con',
        'win32security',
        'win32api',
        'pywintypes',
        # WSGI server
        'waitress',
        # Project modules resolved dynamically by the rule engine
        'rules',
        'linux_rules',
        'sigma_rules',
        'correlation',
        'anomaly',
        'soar',
        'ai_summary',
        'query_lang',
        'notifier',
        'report',
        'cases',
        'saved_queries',
        'rule_management',
        'syslog_listener',
        'collector',
        'ingest',
        'bas',
        'paths',
        # reportlab pulls these in only at PDF-render time
        'reportlab.graphics.barcode',
        'reportlab.pdfbase._fontdata',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Not used anywhere - excluding these cuts roughly 200MB off the
        # bundle. If you later add charting server-side, remove these.
        #
        # PIL is deliberately NOT excluded: reportlab.lib.utils imports it
        # at runtime (used for embedding images in generated PDF reports,
        # e.g. Sentinel_BAS_Coverage_Report.pdf). Excluding it caused
        # ModuleNotFoundError the moment report.py was touched.
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'tkinter',
        'PyQt5',
        'PySide2',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='MiniSIEM',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Drop a .ico next to this file and uncomment to brand the exe.
    # icon='minisiem.ico',
)
