# My Simple Crackme Project

This repository contains the "crackme" project, a program that utilizes various protection techniques, including:

- String encryption during compilation
- Dynamic code integrity checks during runtime using CRC32
- 4 anti-debugging methods
- 3 anti-disassembly methods
- 2 virtual machine detection methods
- Using an exception to control the flow of execution
- Minor obfuscation and fake checks

The program reads a password from a file called `password.txt` located in the same directory as the executable. It then checks the entered password, and if the check is successful, it generates a serial key in the format "KEY$..." and writes it to a file named `serial.txt`.

## Development and Testing Environment

The successful compilation and testing were done using the following tools and environment:

- Visual Studio Build Tools v143
- Windows 11 SDK (10.0.22000.0)
- Python 3.11.3
- pefile 2023.2.7

The compilation and program execution are supported only on Windows x64. Successful tests were performed on Windows 11 Pro 22H2 22621.2283.

## Usage

To compile and run the program, ensure you have the specified development environment set up. Then, simply build the project and run the resulting executable.

## Contributing

Contributions to improve or expand this crackme project are welcome! Feel free to submit pull requests, report issues, or suggest new features.

## License

This project is licensed under the [MIT License](LICENSE).
