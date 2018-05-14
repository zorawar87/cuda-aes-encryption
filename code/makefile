cuda: clean begin cuda_compile cuda_enc 

begin: keygen payload 

key: keygen

payload: gen_payload

keygen: keygen_compile
	./keygen

keygen_compile:
	gcc keygen.c -o keygen

gen_payload: gen_payload_compile
	./gen_payload

gen_payload_compile:
	gcc gen_payload.c -o gen_payload

cuda_compile:
	nvcc aes.cu -o aesEncrypt

cuda_enc:
	./aesEncrypt payload cuda.enc key 

test_cuda:
	hexdump cuda.enc | less

test_ssl:
	hexdump ssl.enc | less

ssl:
	openssl enc -aes-128-cbc -in payload -out ssl.enc

clean:
	rm -f a.out gen_payload aesEncrypt keygen
	rm -f reassemble ssl.enc cuda.enc key payload

