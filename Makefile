.PHONY: build

build:
	g++ encrypt_test.cpp EncryptProcess.cpp -o encrypt_test
build_pg:
	g++ encrypt_test.cpp EncryptProcess.cpp -pg -o encrypt_test
