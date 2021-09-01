import setuptools

version = "0.0.1"
setuptools.setup(
    name="pyvnc_sync",
    version=version,
    author="ORNL",
    author_email="weberb@ornl.gov",
    description="Very simple synchronous VNC client",
    packages=setuptools.find_packages(),
    install_requires=["des", "pillow"],
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    python_requires='>=3.6',
)
