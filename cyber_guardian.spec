# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Specification for Cyber Guardian Standalone Desktop App
Bundles Streamlit, pywebview, Altair, and Google GenAI into CyberGuardian.exe
"""

import os
import sys
from PyInstaller.utils.hooks import collect_data_files, copy_metadata, collect_submodules

block_cipher = None

# Workspace root
project_dir = os.path.abspath(SPECPATH)

# Data files collection
datas = [
    (os.path.join(project_dir, 'src'), 'src'),
    (os.path.join(project_dir, '.streamlit'), '.streamlit'),
]

# Collect package data files
datas += collect_data_files('streamlit')
datas += collect_data_files('altair')
datas += collect_data_files('webview')

# Collect metadata required by runtime packages (importlib.metadata)
datas += copy_metadata('streamlit')
datas += copy_metadata('google-genai')
datas += copy_metadata('pydantic')

# Hidden imports
hiddenimports = [
    # Core Streamlit
    'streamlit',
    'streamlit.web.cli',
    'streamlit.runtime.scriptrunner.magic_expressions',
    'streamlit.runtime.caching',
    'streamlit.runtime.state',
    'streamlit.web.server.server',

    # PyWebview and Windows Webview2
    'webview',
    'webview.platforms.winforms',
    'webview.platforms.edgechromium',
    'clr',
    'clr_loader',

    # Database & System
    'sqlite3',
    'multiprocessing',

    # GenAI & Validation
    'google.genai',
    'pydantic',
    'pydantic.deprecated.decorator',

    # Environment
    'dotenv',
    'python-dotenv',
]

# Collect submodules
hiddenimports += collect_submodules('streamlit')
hiddenimports += collect_submodules('src')
hiddenimports += collect_submodules('google.genai')
hiddenimports += collect_submodules('pydantic')

# Console window toggle: default to False (clean windowed GUI), can be enabled via PYINSTALLER_CONSOLE=1
console_mode = os.getenv('PYINSTALLER_CONSOLE', '0').lower() in ('1', 'true', 'yes')

a = Analysis(
    ['run_app.py'],
    pathex=[project_dir],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'notebook', 'IPython', 'pytest'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher,
)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CyberGuardian',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=console_mode,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
