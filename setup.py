from setuptools import setup, find_packages

setup(
    name="phantomrecon",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "phantomrecon": [
            "wordlists/*.txt",
            "signatures/*.json",
            "signatures/*.yaml",
        ],
    },
    install_requires=[
        "aiohttp>=3.9.0",
        "aiohttp-socks>=0.8.4",
        "rich>=13.7.0",
        "click>=8.1.7",
        "beautifulsoup4>=4.12.3",
        "lxml>=5.1.0",
        "jinja2>=3.1.3",
        "aiofiles>=23.2.1",
        "PyYAML>=6.0.1",
        "certifi>=2024.2.2",
    ],
    entry_points={
        "console_scripts": [
            "phantomrecon=phantomrecon.cli:run",
            "phantomrecon-gui=phantomrecon.gui:run_gui",
        ],
    },
    python_requires=">=3.10",
)
