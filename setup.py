from setuptools import setup


with open("README.md") as f:
    readme = f.read()

setup(
    name="samurai",
    version="0.0.1",
    long_description=readme,
    author="Filip Świszcz"
)