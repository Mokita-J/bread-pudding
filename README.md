**Requirements:**
- Openssl
- C++

**Compile generic test:**
`g++ test.cpp -I/opt/ssl/include/ -L/opt/ssl/lib/ -lcrypto -o test`

**Run generic test:**
`./test <input_file>`

**Current assumptions:**
- File is previously encrypted to maximize its entropy and privacy
    + encrypt `openssl aes-256-cbc -a -salt -pbkdf2 -in <og_filename> -out <enc_filename>`
    + decrypt `openssl aes-256-cbc -d -a -pbkdf2 -in <enc_filename> -out <og_filename>`
- All the template parameters generate a complete Merkle Tree


**TODO:**
- Input verification
- Documentation
- Complete readme
