#include <stdio.h>
#include <pthread.h>
#include <unistd.h> //usleep, getpid
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include "lz4.c"

int main(int argc, char **argv)
{
    if (argc != 2)
        return -1;
    FILE *fp = fopen(argv[1], "rb");

    int log_size;
    fread(&log_size, sizeof(uint64_t), 1, fp);
    char *compressed_data = calloc(sizeof(char), log_size);
    fseek(fp, 0, SEEK_END);
    int filesize = ftell(fp) - sizeof(int);

    fseek(fp, sizeof(uint64_t), SEEK_SET);
    const uint64_t compressed_data_size = fread(compressed_data, sizeof(char), filesize, fp);
    fclose(fp);
    char *const regen_buffer = (char *)malloc(log_size);
    if (regen_buffer == NULL)
        puts("Failed to allocate memory for *regen_buffer.");
    // The LZ4_decompress_safe function needs to know where the compressed data is, how many bytes long it is,
    // where the regen_buffer memory location is, and how large regen_buffer (uncompressed) output will be.
    // Again, save the return_value.
    const int decompressed_size = LZ4_decompress_safe(compressed_data, regen_buffer, compressed_data_size, log_size);
    free(compressed_data); /* no longer useful */

    if (decompressed_size < 0)
        puts("A negative result from LZ4_decompress_safe indicates a failure trying to decompress the data.  See exit code (echo $?) for value returned.");
    if (decompressed_size >= 0)
        printf("We successfully decompressed some data!\n");
    // Not only does a positive return value mean success,
    // value returned == number of bytes regenerated from compressed_data stream.
    if (decompressed_size != log_size)
        puts("Decompressed data is different from original! \n");
    // puts(regen_buffer);
    char *filename_out = (char *)calloc(strlen(argv[1]) + 3, sizeof(char));
    strtok(argv[1], "_c.log");
    sprintf(filename_out, "%s_d.log", argv[1]);
    fp = fopen(filename_out, "w");
    fwrite(regen_buffer, sizeof(char), decompressed_size, fp);
    fclose(fp);
}