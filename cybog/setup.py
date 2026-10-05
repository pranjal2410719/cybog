from setuptools import setup, find_packages

setup(
    name="cybog",
    version="1.0.0",
    description="Authorized Security Assessment Workflow Engine",
    author="Project Cybog",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "cybog=cybog.cli.main:app",
        ]
    },
    install_requires=[
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
        "typer[all]>=0.9.0",
        "rich>=13.0.0",
    ],
    python_requires=">=3.10",
)
