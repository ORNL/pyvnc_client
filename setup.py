import setuptools

setuptools.setup(
    name="pyvnc_sync",
    version="0.0.0.dev3",
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
