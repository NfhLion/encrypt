#include "EncryptProcess.h"
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include<sys/time.h>

#define MSGSIZE 512

int readFile(const string& filename, ByteArray& vc) {
    uint8_t buff[1024] = {0};
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd < 0) {
        printf("error: open file failed!\n");
        return 1 ;
    }
    int ret;
    while ((ret = read(fd, buff, 1024)) > 0) {
        vc.insert(vc.end(), buff, buff + ret);
        memset(buff, 0, 1024);
    }
    if (ret < 0) {
        printf("read file failed!\n");
        close(fd);
        return 2;
    }
    close(fd);
    return 0;
}

int writeFile(const string& filename, ByteArray&& vc) {
    printf("vc.size = %ld\n", vc.size());
    int fd = open(filename.c_str(), O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) {
        printf("error: open file failed!\n");
        return 1 ;
    }

    int ret;
    // int len = MSGSIZE;
    // int n = 0;
    
    // while ((ret = write(fd, msg + n, len)) > 0) {
    //     if (ret < len)
    //         break;
    //     n += ret;
    //     printf("ret = %d, n = %d\n", ret, n);
    // }
    // printf("ret = %d\n", ret);
    ret = write(fd, vc.data(), vc.size());
    if (ret < 0) {
        printf("write file failed!\n");
        close(fd);
        return 2;
    }
    close(fd);
    return 0;
}

int encryptFile(const string& filename, const string& key) {
    ByteArray file_info;
    int ret = readFile(filename.c_str(), file_info);
    if (ret > 0) 
        return 1;
    ByteArray encrypt_str;
    EncryptProcess item(filename, key);

    struct timeval tBegin, tEnd;
    double time=0;
    gettimeofday(&tBegin, NULL);
    item.encrypt(std::move(file_info), encrypt_str);
    gettimeofday(&tEnd, NULL);
    time = tEnd.tv_sec-tBegin.tv_sec + (tEnd.tv_usec-tBegin.tv_usec)/1000000.0;
    printf("< encrypt > [ %s ] need %5.3lf ms\n", filename.c_str(), time * 1000);

    string new_file = "encrypt_dir/" + string(filename.begin() + filename.find_last_of("/") + 1, filename.end());
    std::cout << "new_file: " << new_file << std::endl;
    ret = writeFile(new_file.c_str(), std::move(encrypt_str));
    if (ret > 0) 
        return 1;
    return 0;
}

int decryptFile(const string& filename, const string& key) {
    ByteArray file_info;
    int ret = readFile(filename.c_str(), file_info);
    if (ret > 0) 
        return 1;
    ByteArray decrypt_str;
    DecryptProcess item(filename, key);
    uint8_t* msg = (uint8_t*)malloc(file_info.size());
    memcpy(msg, file_info.data(), file_info.size());

    struct timeval tBegin, tEnd;
    double time=0;
    gettimeofday(&tBegin, NULL);
    ret = item.decrypt(msg, file_info.size(), decrypt_str);
    gettimeofday(&tEnd, NULL);
    time = tEnd.tv_sec-tBegin.tv_sec + (tEnd.tv_usec-tBegin.tv_usec)/1000000.0;
    printf("< decrypt > [ %s ] need %5.3lf ms\n", filename.c_str(), time * 1000);
    if (ret > 0) {
        return -1;
    }
    
    free(msg);
    msg = NULL;

    string new_file = "decrypt_dir/" + string(filename.begin() + filename.find_last_of("/") + 1, filename.end());
    std::cout << "new_file: " << new_file << std::endl;

    ret = writeFile(new_file.c_str(), std::move(decrypt_str));
    if (ret > 0) 
        return 1;
    
    return 0;
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("please input params!\n");
        printf("=====> e|d, filename, (key)\n");
        return 1;
    }

    char c = argv[1][0];
    switch (c) {
        case 'e': encryptFile(string(argv[2]), string(argv[3])); break;
        case 'd': decryptFile(string(argv[2]), string(argv[3])); break;
    }

    return 0;
}