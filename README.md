
__________          


## Overview

This repositiory contains scripts designed to identify potential vulnerabilities in Android apps. 

This tool currently scans APK files to detect exported activities that have 'android.intent.action.CALL' in their intent filters, which can expose dangerous permissions, posing security risks to users.

**Note: This project is a work in progress (WIP) and is currently under development.**

## Features

- Scans APK files for exported activities with 'android.intent.action.CALL' intent filters.
- Identifies potential vulnerabilities in Android phone dialer apps.
- Parses APK files to extract manifest information.
- Provides example ADB commands to test the identified activities.

## Dependencies

Dialer.py requires the following dependencies:

- [apktool](https://ibotpeaches.github.io/Apktool/) (for decoding APK files)
- Python 3.x

## How it Works

Dialer.py parses APK files to extract their manifest information. It then searches for exported activities that handle 'android.intent.action.CALL' intents. Once potential vulnerabilities are detected, the tool generates example ADB commands to test the identified activities.

## Usage

To use Dialer.py, simply provide the path to an APK file or directory containing multiple APK files as a command-line argument. The tool will analyze each APK file and display the results.

```
python dialer.py <apk_file or directory>
```

## Example

Suppose you have an APK file named `example.apk`. To scan this file for potential vulnerabilities, run the following command:

```
python dialer.py example.apk
```

The tool will analyze the APK file and display any identified vulnerabilities, along with example ADB commands to test the exported activities.

## Contributing

Contributions to Dialer.py are welcome! If you'd like to contribute, please fork the repository, make your changes, and submit a pull request. We appreciate any contributions that improve the functionality and usability of the tool.

## License

This project is licensed under the MIT License. 

---
