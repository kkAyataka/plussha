plussha
=======

Header only C++ SHA library.

## Development / Test Environment

* Xcode 8.3 (Apple LLVM 8.1)


## Supported SHA

* SHA-256


## Usage

```c++
#include "plussha/plussha256.hpp"

int main() {
    const char * data = "abc";
    unsigned char hash[32] = {};
    plussha::sha256((unsigned char*)data, strlen(data), &hash);
}
```

## License
[Boost Software License](LICENSE_1_0.txt)
