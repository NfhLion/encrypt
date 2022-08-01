.PHONY: build build_pg build_asan

build:
	g++ encrypt_test.cpp EncryptProcess.cpp -o encrypt_test
build_pg:
	g++ encrypt_test.cpp EncryptProcess.cpp -pg -o encrypt_test
build_asan:
	g++ -fsanitize=address -fno-omit-frame-pointer -O1 -g encrypt_test.cpp EncryptProcess.cpp -o encrypt_test

# gcc -fsanitize=address -fno-omit-frame-pointer -O1 -g use-after-free.c -o use-after-free