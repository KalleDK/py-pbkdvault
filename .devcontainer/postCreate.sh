#/usr/bin/env sh
python -m pip install --user .[testing]
python -m pip uninstall pbkdvault -y
python setup.py develop --user