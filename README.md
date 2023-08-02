# Bootloaders.io - Tracking and Cataloging Malicious Bootloaders 🚀

![CI build](https://github.com/magicsword-io/Bootloaders/actions/workflows/validate.yml/badge.svg)

Welcome to Bootloaders.io, an open-source project that brings together known malicious Bootloaders for various operating systems in one comprehensive repository. Our mission is to empower organizations of all sizes with the knowledge and tools to understand and address bootloader-related security risks, making their systems safer and more reliable.

## Key Features

- An extensive and well-organized collection of known malicious Bootloaders
- Continuously updated with the latest information on bootloader threats
- Easy-to-navigate categories and indices for quick access to relevant information
- Seamless integration with Sigma for proactive defense using hash prevention

## How Bootloaders.io Can Help Your Organization

- Enhance visibility into malicious Bootloaders within your infrastructure, fostering a stronger security posture
- Stay ahead of the curve by being informed about the latest bootloader-related threats
- Swiftly identify and address risks associated with Bootloaders, minimizing potential damages
- Leverage compatibility with Sigma to proactively block known malicious Bootloaders by hash

## Getting Started

To begin your journey with Bootloaders.io, simply check out the [Bootloaders.io](https://Bootloaders.io/) site or clone the repository and explore the wealth of information available in the categorized directories. We've designed the site to help you easily find the insights you need to protect your systems from malicious Bootloaders.

## Support 📞

Please use the [GitHub issue tracker](https://github.com/magicsword-io/Bootloaders/issues) to submit bugs or request features.

## 🤝 Contributing & Making PRs

Stay engaged with the Bootloaders.io community by regularly checking for updates and contributing to the project. Your involvement will help ensure the project remains up-to-date and even more valuable to others.

Join us in our quest to create a safer and more secure digital environment for organizations everywhere. With Bootloaders.io by your side, you'll be well-equipped to tackle bootloader-related security risks and confidently navigate the ever-evolving cyber landscape.

If you'd like to contribute, please follow these steps:

1. Fork the repository
2. Create a new branch for your changes
3. Make your changes and commit them to your branch
4. Push your changes to your fork
5. Open a Pull Request (PR) against the upstream repository

For more detailed instructions, please refer to the [CONTRIBUTING.md](CONTRIBUTING.md) file. To create a new YAML file for a bootloader, use the provided [YML-Template](YML-Template.yml).

## 🚨 Sigma and Sysmon Detection

Bootloaders.io provides comprehensive Sigma and Sysmon detection rules to help you effectively detect potential threats. To explore these rules in detail, navigate to the [sigma](detections/sigma/) and [sysmon](detections/sysmon/) directories under the detection folder.

Happy hunting! 🕵️‍♂️

## 🔎 Bootloader Atomic Testing and Inventory

Atomic Testing with a PowerShell bootloader utility courtesy of [@MHaggis] may be found [here](https://github.com/MHaggis/notes/blob/master/utilities/theBoots.ps1), that assists with modifying the registry related to Bootloaders on the endpoint. 

If using Splunk or another method of inventory, a Splunk Scripted Inputs may be used from [here](https://gist.github.com/MHaggis/26518cd2844b0e03de6126660bb45707). 

Want to view your Boots? Simple as this:

`bcdedit /enum /v`

## 🏗️ Building and Testing Locally

### Requirements

* [Python 3.10](https://www.python.org/downloads/)
* [Poetry](https://python-poetry.org/docs/#installation)
* [Golang](https://go.dev/dl/)
* [Hugo](https://gohugo.io/)

### Steps to Build and Test Locally

1. Clone the repository:

```
git clone https://github.com/magicsword-io/Bootloaders.git
```

2. Change to the project directory:

```
cd Bootloaders
```

3. Install dependencies:

```
poetry install
```

4. Activate the virtual environment:

```
poetry shell
```

5. Build the site using the files under the /yaml folder:

```
python bin/site.py
```

6. Run the website locally:

```
cd Bootloaders.io && hugo serve
```
