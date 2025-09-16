#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    int its = std::atoi(argv[1]);

    for (int i=0; i<its; i++) {
        // get random byte
        int fd = open("/dev/random", O_RDONLY);
        if (!fd)
            return 1;
        uint8_t random_byte;
        if (read(fd, &random_byte, 1) != 1)
            return 1;
        close(fd);

        // print a message
        if (random_byte%2)
            write(1, "hello", 5);
        else
            write(1, "goodbye", 7);
        write(1, " world!\n", 8);
    }

    return 0;
}
