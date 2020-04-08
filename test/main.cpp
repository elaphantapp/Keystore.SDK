
#include "../crypto/bip39.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

void TestGenrateMnemonic();

const char *c_help = \
    "genmne    test generate mnemonic.\n" \
    "help      show help message.\n" \
    "exit      exit the test program.\n" \
    "\n";

int main(int argc, char *argv[])
{
    std::cout << "input command: ";
    while(1)
    {
        std::string command;
        std::getline(std::cin, command);
        if (!command.compare("genmne")) {
            TestGenrateMnemonic();
        }
        else if (!command.compare("help")) {
            std::cout << c_help;
        }
        else if (!command.compare("exit")) {
            break;
        }
        else if (command.length() != 0){
            std::cout << "not support command\n";
        }
    }

    return 0;
}

void TestGenrateMnemonic()
{
    printf("============== start TestGenrateMnemonic ==============\n");
    int len = generateMnemonic(128, "english", NULL);
    char phrase1[len];

    len = generateMnemonic(128, "english", phrase1);
    if (len < 0) {
        printf("generate mnemonic failed: %d\n", len);
    }
    printf("mnemonic 1: %s\n", phrase1);

    bool valid = checkMnemonic(phrase1);
    printf("check mnemonic %d\n", valid);

    int len2 = generateMnemonic(160, "chinese", NULL);
    char phrase2[len2];
    len2 = generateMnemonic(160, "chinese", phrase2);
    if (len2 < 0) {
        printf("generate mnemonic failed: %d\n", len2);
    }
    printf("mnemonic 2: %s\n", phrase2);

    valid = checkMnemonic(phrase2);
    printf("check mnemonic %d\n", valid);

    printf("============== end TestGenrateMnemonic ==============\n");
}
