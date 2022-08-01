#include "EncryptProcess.h"


int EncryptProcess::dataUpset(uint8_t* buff, size_t len) {
    if (!buff) {
        printf("error: string buffer is NULL!\n");
        return 1;
    }

    int interval = headInfo.interval;
    int byteBlockSize = headInfo.byteBlockSize;
    int block_nums = len / byteBlockSize;
    uint8_t* block = (uint8_t *)malloc(byteBlockSize);
    if (!block) {
        printf("error: malloc memory failed!\n");
        return 2;
    }
    
    for (int i = interval; i < block_nums; i += interval) {
        for (int j = i - interval; j < interval / 2; j++) {
            uint8_t* bfp1 = buff + j*byteBlockSize;
            uint8_t* bfp2 = buff + (j+interval/2)*byteBlockSize;
            memcpy(block, bfp1, byteBlockSize);
            memcpy(bfp1, bfp2, byteBlockSize);
            memcpy(bfp2, block, byteBlockSize);
        }
    }
    free(block);
    block = NULL;
    return 0;
}

int EncryptProcess::encrypt(const ByteArray& input, ByteArray& output) {
    return encrypt(input.data(), input.size(), output);
}

int EncryptProcess::encrypt(const ByteArray&& input, ByteArray& output) {
    return encrypt(input.data(), input.size(), output);
}

int EncryptProcess::encrypt(const uint8_t* input, size_t len, ByteArray& output) {
    int ret;
    if (!input) {
        printf("error: string buffer is NULL!\n");
        return 1;
    }
    uint8_t encryptHead[HEAD_SIZE] = {0};
    // first encrypt
    int mod = len % headInfo.byteBlockSize;
    if (mod > 0) {
        headInfo.fillSize = headInfo.byteBlockSize - mod;
    }
    mod = headInfo.filenameSize % headInfo.byteBlockSize;
    if (mod > 0) {
        headInfo.filenameSize += headInfo.byteBlockSize - mod;
    }

    size_t buff_len = sizeof(encryptHead) + headInfo.keySize + headInfo.filenameSize + len + headInfo.fillSize;
    uint8_t* buff = (uint8_t *)malloc(buff_len);
    if (!buff) {
        printf("error: malloc memory failed!\n");
        return 2;
    }
    memset(buff, 0, sizeof(buff_len)); 
    int eh_len = sizeof(encryptHead);
    int key_len = headInfo.keySize;
    int filename_len = headInfo.filenameSize;
    memcpy(encryptHead, (uint8_t*)(&headInfo), sizeof(headInfo));
    memcpy(buff, encryptHead, eh_len);         // add head
    memcpy(buff+eh_len, encryptKey.c_str(), key_len);    // add h_key
    memcpy(buff+eh_len+key_len, mDataName.c_str(), mDataName.length()); // add filename
    memcpy(buff+eh_len+key_len+filename_len, input, len);    // add headInfo

    // first encrypt
    ret = dataUpset(buff + eh_len + key_len + filename_len, len + headInfo.fillSize);
    if (ret) {
        printf("Encrypt Failed!\n");
        free(buff);
        buff = NULL;
    }
    // second encrypt
    ret = dataUpset(buff + eh_len + key_len, filename_len + len + headInfo.fillSize);
    if (ret) {
        printf("Encrypt Failed!\n");
        free(buff);
        buff = NULL;
    }

    output.insert(output.begin(), buff, buff + buff_len);
    free(buff);
    buff = NULL;

    printf("---------------------------------- Encrypt success!---------------------------------\n");

    return 0;
}

int DecryptProcess::dataRecover(uint8_t* buff, size_t len) {
    if (!buff) {
        printf("error: string buffer is NULL!\n");
        return 1;
    }

    int interval = headInfo.interval;
    int byteBlockSize = headInfo.byteBlockSize;
    int block_nums = len / byteBlockSize;
    uint8_t* block = (uint8_t *)malloc(byteBlockSize);
    if (!block) {
        printf("error: malloc memory failed!\n");
        return 2;
    }
    
    for (int i = interval; i < block_nums; i += interval) {
        for (int j = i - interval; j < interval / 2; j++) {
            uint8_t* bfp1 = buff + j*byteBlockSize;
            uint8_t* bfp2 = buff + (j+interval/2)*byteBlockSize;
            memcpy(block, bfp1, byteBlockSize);
            memcpy(bfp1, bfp2, byteBlockSize);
            memcpy(bfp2, block, byteBlockSize);
        }
    }
    free(block);
    block = NULL;
    return 0;
}

int DecryptProcess::decrypt(uint8_t* input, size_t len, ByteArray& output) {
    uint8_t head[HEAD_SIZE] = {0};
    memcpy(head, input, HEAD_SIZE);
    headInfo = *((EncryptHead*)head);

    {
        printf("headInfo.fillSize = %ld\n", headInfo.fillSize);
        printf("headInfo.filenameSize = %ld\n", headInfo.filenameSize); //
        printf("headInfo.keySize = %ld\n", headInfo.keySize); //
    }

    int keySize = headInfo.keySize;
    int filenameSize = headInfo.filenameSize;
    int fillSize = headInfo.fillSize;

    input += HEAD_SIZE;
    len -= HEAD_SIZE;
    int cmp = memcmp(input, (uint8_t*)decryptKey.data(), keySize);
    if (cmp != 0) {
        printf("key is no ok!\n");
        return 1;
    } 

    // first decrypt
    input += keySize;
    len -= keySize;
    int ret = dataRecover(input, len);
    
    // second decrypt
    input += headInfo.filenameSize;
    len -= headInfo.filenameSize;
    ret = dataRecover(input, len);

    // del fill bytes
    len -= headInfo.fillSize;

    output.insert(output.begin(), input, input + len);

    printf("---------------------------------- Decrypt success!---------------------------------\n");

    return 0;
}
