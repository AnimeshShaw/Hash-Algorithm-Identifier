from distutils.core import setup

try:
    import py2exe
except ImportError:
    print("Python 3.x is required to create Windows binaries.")

setup(console=['hashidentifier/HashIdentifier.py'])