#!/usr/bin/bash

poetry build
python3 -m pip install $(ls dist/*.tar.gz)