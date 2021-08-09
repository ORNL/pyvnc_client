import os
import setuptools

version = os.getenv("VERSION")
if version is None:
    version = "0.0.0.dev0"

setuptools.setup(
    name="pyvnc_sync",
    version=version,
    author="ORNL",
    author_email="weberb@ornl.gov",
    description="Very simple synchronous VNC client",
    packages=setuptools.find_packages(),
    install_requires=["des"],
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    python_requires='>=3.6',
)
