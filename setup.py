from setuptools import setup
import sys

requires = ["httpx>=0.23.0"]

if sys.version_info < (3, 9):
    sys.exit("Sorry, Python < 3.9 is not supported")

setup(
    name="aio-kavenegar",
    version="2.0.1",
    description="AsyncIO compatible Kavenegar Python library",
    author="Alireza Jafari (Original project by Kavenegar Team)",
    author_email="alirezaja1384@gmail.com",
    url="https://github.com/alirezaja1384/aio-kavenegar",
    keywords=["kavenegar", "sms", "asyncio"],
    install_requires=requires,
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
        "Development Status :: 5 - Production/Stable",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Communications :: Telephony",
    ],
)
