typedef unsigned int size_t;
long write(int descriptor, const void *buffer, size_t length)
{
    (void)descriptor;
    (void)buffer;
    (void)length;
    return -1;
}
