# Introduction

Enable hardware acceleration (OPTIGA™ TPM 2.0) on Mbed TLS.

# Table of Contents

# Prerequisites

- Tested on Raspberry Pi 4 Model B with Iridium 9670 TPM 2.0 board [[1]](#1) 
- Set up the Raspberry Pi according to [[2]](#2)

# Mbed TLS Library

```
$ git clone https://github.com/ARMmbed/mbedtls ~/mbedtls
$ cd mbedtls
$ git checkout mbedtls-2.28.0 
$ cd library
$ make
```

Header files: `~/mbedtls/include/mbedtls/`<br>
Static libraries: `~/mbedtls/library/libmbedcrypto.a`, `~/mbedtls/library/libmbedtls.a`, and `~/mbedtls/library/libmbedx509.a`

# References

<a id="1">[1] https://www.infineon.com/cms/en/product/evaluation-boards/iridium9670-tpm2.0-linux/</a><br>
<a id="2">[2] https://github.com/wxleong/tpm2-rpi4</a><br>

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
