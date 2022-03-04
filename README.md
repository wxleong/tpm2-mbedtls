# Introduction

Enable crypto accelerator (OPTIGA™ TPM 2.0) on Mbed TLS.

# Table of Contents

- **[Prerequisites](#prerequisites)**
- **[Mbed TLS Library](#mbed-tls-library)**
- **[Sample Application](#sample-application)**
- **[References](#references)**
- **[License](#license)**

# Prerequisites

- Tested on Raspberry Pi 4 Model B with Iridium 9670 TPM 2.0 board [[1]](#1) 
- Set up the Raspberry Pi according to [[2]](#2)
- Grant access to TPM device node:
    ```
    $ sudo chmod a+rw /dev/tpmrm0
    ```

# Mbed TLS Library

```
$ git clone https://github.com/ARMmbed/mbedtls ~/mbedtls
$ cd ~/mbedtls
$ git checkout mbedtls-2.28.0 
$ cd library
$ make
```

The following items are copied to [code/mbedtls-2.28.0](https://github.com/wxleong/tpm2-mbedtls/tree/develop-genesis/code/mbedtls-2.28.0):
- Header files: `~/mbedtls/include/mbedtls/`
- Static libraries: `~/mbedtls/library/libmbedcrypto.a`, `~/mbedtls/library/libmbedtls.a`, and `~/mbedtls/library/libmbedx509.a`

# Sample Application

```
$ git clone https://github.com/wxleong/tpm2-mbedtls ~/tpm2-mbedtls
$ cd ~/tpm2-mbedtls/code
$ make
$ ./main
```

# References

<a id="1">[1] https://www.infineon.com/cms/en/product/evaluation-boards/iridium9670-tpm2.0-linux/</a><br>
<a id="2">[2] https://github.com/wxleong/tpm2-rpi4</a><br>

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# To-do

- Check signature output buffer size in `tpm_ecp_sign` and `tpm_rsa_sign` is suffice to avoid segmentation fault
- Move `pk_tpm_ecp_init` `pk_tpm_rsa_init` into `tpm_ecp_alloc` `tpm_rsa_alloc`
- Integrate into https://github.com/open62541/open62541
