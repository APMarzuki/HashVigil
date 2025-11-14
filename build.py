import PyInstaller.__main__
import os
import shutil


def build_executable():
    print("Building HashVigil executable...")

    # Clean previous builds
    if os.path.exists('dist'):
        shutil.rmtree('dist')
    if os.path.exists('build'):
        shutil.rmtree('build')

    PyInstaller.__main__.run([
        'main.py',
        '--onefile',
        '--windowed',
        '--name=HashVigil',
        '--add-data=config;config',
        '--hidden-import=PyQt5.QtWidgets',
        '--hidden-import=PyQt5.QtCore',
        '--hidden-import=requests',
        '--clean'
    ])

    print("Build completed! Check the 'dist' folder for HashVigil.exe")


if __name__ == "__main__":
    build_executable()