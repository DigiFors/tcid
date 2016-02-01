# TCID
Identifies TrueCrypt containers

## Usage
`./tcid.py --help`

## How it works
Similar to TCHunt, TCID uses a three-step process to sniff out TrueCrypt containers:
1. Check the file size. TrueCrypt containers have a minimum size of 15 KiB and a maximum size of 1 PiB, with the file size divisible by 512.
2. Check the file type. libmagic can't identify TrueCrypt containers.
3. Check the bytes of the file for an uniform distribution using a chi-squared test. TrueCrypt containers are closer to the uniform distribution than other files.

All tests can be switched off; the p-value for the chi-squared test can be adjusted.

## Dependencies
* python-magic, `pip install python-magic`
* [SciPy](https://www.scipy.org/)

## License
MIT