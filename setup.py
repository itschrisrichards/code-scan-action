from setuptools import find_packages, setup

VERSION = "0.1.0"
DESCRIPTION = "Pre-commit hook to scan staged commit files for PII."


setup(
    name="code_scan_action",
    version=VERSION,
    author="Louper AI",
    description=DESCRIPTION,
    packages=find_packages(),
    install_requires=[
        "requests==2.28.1",
        "python-dotenv==0.19.0",
        "unidiff~=0.7.4",
    ],
    keywords=["python", "pre-commit"],
    entry_points={"console_scripts": ["code_scan_action=code_scan_action.code_scan_action:main"]},
)
