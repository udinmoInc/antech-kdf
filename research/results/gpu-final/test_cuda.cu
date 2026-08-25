#include <stdio.h>
#include <cuda_runtime.h>

__global__ void hello_kernel() {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx == 0) {
        printf("CUDA Kernel Execution Successful on GPU!\n");
    }
}

int main() {
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);
    printf("GPU Device: %s\n", prop.name);
    printf("VRAM Total: %zu MB\n", prop.totalGlobalMem / (1024 * 1024));
    printf("Compute Capability: %d.%d\n", prop.major, prop.minor);

    hello_kernel<<<1, 32>>>();
    cudaDeviceSynchronize();
    return 0;
}
