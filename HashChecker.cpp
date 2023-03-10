#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <openssl/sha.h>

using namespace std;

bool check_password(const string& password, const string& hashed_password) {
    // Hash the password
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.size());
    SHA256_Final(hash, &sha256);

    // Compare the hashed password with the hash from the list
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    string hex_hash = ss.str();
    if (hex_hash == hashed_password) {
        return true;
    } else {
        return false;
    }
}

int main() {
    ifstream infile("passwords.txt");
    string password;
    string hashed_password = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";

    while (infile >> password) {
        if (check_password(password, hashed_password)) {
            cout << "Password found: " << password << endl;
            return 0;
        }
    }
    cout << "Password not found in the list" << endl;
    return 0;
}
