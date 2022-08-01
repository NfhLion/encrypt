#ifndef FILE_ENCRYPT_H
#define FILE_ENCRYPT_H
#include <string>
#include <stdio.h>
#include <vector>
#include <string.h>

#define DEFAULT_KEY "MEGA"
#define DEFAULT_NAME "MSSAGE"
#define HEAD_SIZE 64
#define DEFAULT_BYTEBLOCKSIZE 16
#define DEFAULT_INTERVAL 4

using namespace std;

struct EncryptHead {
    size_t byteBlockSize;
    int interval;
    size_t fillSize;
    size_t keySize;
    size_t filenameSize;
};

using ByteArray = vector<uint8_t>;

class EncryptProcess {
public:
    EncryptProcess(const string& dataName = DEFAULT_NAME, string key = DEFAULT_KEY) 
        : mDataName(dataName), encryptKey(key)
    {
        headInfo.keySize = encryptKey.length() + 1;
        headInfo.filenameSize = mDataName.length() + 1;
        headInfo.fillSize = 0;
        setEncryptParams();
    }
    ~EncryptProcess() {}

    int encrypt(const uint8_t* input, size_t len, ByteArray& output);
    int encrypt(const ByteArray& input, ByteArray& output);
    int encrypt(const ByteArray&& input, ByteArray& output);

    void setEncryptParams(size_t byteBlockSize = DEFAULT_BYTEBLOCKSIZE, int interval = DEFAULT_INTERVAL) {
        headInfo.byteBlockSize = byteBlockSize;
        headInfo.interval = interval;
    }

    void setEncryptKey(const string& key) {
        encryptKey = key;
        headInfo.keySize = encryptKey.length() + 1;
    }
private:

    int dataUpset(uint8_t* buff, size_t len);

    EncryptHead headInfo;

    string encryptKey;
    string mDataName;
};

class DecryptProcess {
public:
    DecryptProcess(const string& dataname = DEFAULT_NAME, string key = DEFAULT_KEY) 
        : mDataName(dataname), decryptKey(key)
    {
    }
    ~DecryptProcess() {}

    int decrypt(uint8_t* input, size_t len, ByteArray& output);

private:
    int dataRecover(uint8_t* buff, size_t len);

    EncryptHead headInfo;

    string decryptKey;
    string mDataName;
};

// int decrypt(char* buff, size_t len, const char* key, vector<char>& output);

#endif // FILE_ENCRYPT_H