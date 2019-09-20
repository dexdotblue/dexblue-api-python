import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="dexblue-api-python",
    version="v0.1.0-beta1",
    author="dex.blue",
    author_email="tech@dex.blue",
    description="dex.blue API wrapper for python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/dexdotblue/dexblue-api-py",
    package_data={
        "dexblue": ["config/*"]
    },
    packages=setuptools.find_packages(),
    install_requires=[
        "web3>=5.0.2",
        "websockets>=7.0"
    ],
    license='MIT',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)