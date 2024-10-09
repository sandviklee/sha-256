<h1 align="center" style="font-weight: bold; font-family: Lato; ">SHA-256</h1>

<p align="center">
 <a href="#started">Getting Started</a> • <a href="#comments">Comments</a>
</p>

<p align="center">
    <b>SHA-256 Hashing Algorithm Implemented in C</b>
    <p align="center">SHA-256 is a cryptographic hash function that takes an input and produces a 256-bit (32-byte) hash value. It's widely used in many security applications and protocols.</p>
    <p align="center"><a  href="https://csrc.nist.gov/files/pubs/fips/180-2/upd1/final/docs/fips180-2withchangenotice.pdf">Documentation</a></p>
</p>

<h2 id="pre">Prerequisites</h2>
You need cmake, gcc or clang to compile the project.
 <br/>
 <a href="https://gcc.gnu.org/install/download.html">gcc</a><br/>
 <a href="https://cmake.org/cmake/help/latest/manual/cmake.1.html">cmake</a><br/>

<h2 id="started">🚀 Getting started</h2>

<h3>Cloning</h3>

How to clone this project

```bash
git clone git@github.com:sandviklee/sha-256.git
```

<h3>Running</h3>
Make sure you have all the previous prerequisites installed on your machine.
Then you can run the following commands to compile and run the project:

CMakeList:
```bash
cd build
cmake ..
make; ./sha256
```

GCC:
```bash
gcc ./src/main.c -o build/sha256; ./build/sha256
```

<h2 id="comments">🗯️ Comments</h2>
This project was made for educational purposes only. It is not recommended to use this code in production.

There is still some work to be done, such as:
- [ ] Add support for larger and more blocks to be hashed
- [ ] Fix the compute function to work with N consecutive Hash values... (read docs)
- [ ] Add support for hashing many different types
