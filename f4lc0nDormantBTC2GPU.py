import hashlib
import os
import ecdsa
import time
from multiprocessing import Pool, cpu_count
import numpy as np
import pycuda.driver as cuda
import pycuda.autoinit
from pycuda.compiler import SourceModule
from tqdm import tqdm

def load_hashes(file_name):
    with open(file_name, 'r') as f:
        hashes = set(line.strip() for line in tqdm(f))
    return hashes


mod = SourceModule("""
#include <curand_kernel.h>

extern "C" {
__global__ void generate_random(curandState_t* states, unsigned int* numbers) {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    curand_init(clock64(), idx, 0, &states[idx]);
    numbers[idx] = curand(&states[idx]);
}
}
""", no_extern_c=True)

block_size = 512  
grid_size = 1

func = mod.get_function("generate_random")


def generate_private_keys(start, end):
    n = end - start

    states = cuda.mem_alloc(n * np.intp(0).nbytes)
    numbers = cuda.mem_alloc(n * np.uint32(0).nbytes)

    func(states, numbers, block=(block_size,1,1), grid=(grid_size,1))

    numbers_host = np.empty(n, dtype=np.uint32)
    cuda.memcpy_dtoh(numbers_host, numbers)

    hex_numbers = [format(number, 'X').lstrip('0') for number in numbers_host]
    hex_string = ''.join(hex_numbers)

    # Ensure we only use the first 64 characters
    hex_string = hex_string[:64]

    # If we have less than 64 characters, fill with '0' at the end
    if len(hex_string) < 64:
        hex_string += '0' * (64 - len(hex_string))

    return [hex_string]

"""
def generate_private_keys(start, end):
    return ['38da7147ddaab5b312042a221c7d1ee0ab179c6ffac5a416c153eb4dc7b6d943']
"""


def private_to_public(private_key):
    # Convert a private key to a public key using ECC
    private_key_bytes = bytes.fromhex(private_key)
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key_uncompressed = b'\x04' + vk.to_string()
    y = vk.pubkey.point.y()
    if y & 1:
        public_key_compressed = b'\x03' + vk.to_string()[:32]
    else:
        public_key_compressed = b'\x02' + vk.to_string()[:32]
    return public_key_uncompressed, public_key_compressed

def calculate_ripemd160(public_keys):
    # Calcular los hash 160 RIPEMD de las claves públicas
    ripemd160_hashes = []
    for public_key in public_keys:
        sha256_public_key = hashlib.sha256(public_key).digest()
        ripemd160_sha256_public_key = hashlib.new('ripemd160', sha256_public_key).digest()
        ripemd160_hashes.append(ripemd160_sha256_public_key)
    return ripemd160_hashes


def save_match_result(private_key, ripemd160_hash_uncompressed, ripemd160_hash_compressed):
    with open('matches.txt', 'a') as f:
        f.write(f'Private Key: {private_key}\n')
        f.write(f'UnHash160: {ripemd160_hash_uncompressed}\n')
        f.write(f'ComHash160: {ripemd160_hash_compressed}\n')
        f.write('---\n')


if __name__ == '__main__':

    print(".########.##........##........######....#####...##....##\n.##.......##....##..##.......##....##..##...##..###...##\n.##.......##....##..##.......##.......##.....##.####..##\n.######...##....##..##.......##.......##.....##.##.##.##\n.##.......#########.##.......##.......##.....##.##..####\n.##.............##..##.......##....##..##...##..##...###\n.##.............##..########..######....#####...##....##")
    print("Donate: 1FALCoN194bPQELKGxz2vdZyrPRoSVxGmR" )
    print("sleeping wallet finder V1" )
    print("http://f4lc0n.com" )

    num_processors = cpu_count()

    # Cargar los hashes del archivo
    hashes_to_compare = load_hashes('BTC_h160_file.txt')

    # Dividir el espacio de claves entre los procesos
    keys_per_processor = 1234567
    total_keys = num_processors * keys_per_processor

    pool = Pool(processes=num_processors)

    counter = 0
    start_time = time.time()

    update_interval = 12345678
    processed_keys = 0

    while True:
        # Generate private keys in parallel
        results = []
        for i in range(num_processors):
            start = i * keys_per_processor
            end = start + keys_per_processor
            results.append(pool.apply_async(generate_private_keys, (start, end)))

        # Get the results of the computations
        private_keys = []
        for result in results:
            private_keys.extend(result.get())

        # Convert private keys to public keys
        public_keys_uncompressed, public_keys_compressed = zip(*[private_to_public(private_key) for private_key in private_keys])

        # Calculate RIPEMD-160 hashes on the GPU
        ripemd160_hashes_uncompressed = calculate_ripemd160(public_keys_uncompressed)
        ripemd160_hashes_compressed = calculate_ripemd160(public_keys_compressed)

        counter += total_keys * 2  # Multiplicar por 2 para tener en cuenta los dos hashes generados por cada clave privada
        elapsed_time = time.time() - start_time
        hashes_per_second = counter / elapsed_time

        for i in range(len(private_keys)):
            private_key = private_keys[i]
            ripemd160_hash_uncompressed = ripemd160_hashes_uncompressed[i].hex()
            ripemd160_hash_compressed = ripemd160_hashes_compressed[i].hex()
            #print(f'PKey: {private_key} | UnHash160: {ripemd160_hash_uncompressed} | ComHash160: {ripemd160_hash_compressed}')
    
            # Verificar si los hashes generados están en el conjunto de hashes a comparar
            if ripemd160_hash_uncompressed in hashes_to_compare or ripemd160_hash_compressed in hashes_to_compare:
                print(f'Match found! Private Key: {private_key} | UnHash160: {ripemd160_hash_uncompressed} | ComHash160: {ripemd160_hash_compressed}')
                save_match_result(private_key, ripemd160_hash_uncompressed, ripemd160_hash_compressed)
    
    
            processed_keys += 1

            # Mostrar información en la consola en el intervalo de actualización especificado
            if processed_keys % update_interval == 0:
                print(f'Counter: {counter} | Hashes per second: {hashes_per_second:.2f}', end='\r', flush=True)

        if processed_keys % update_interval != 0:
            print(f'Counter: {counter} | Hashes per second: {hashes_per_second:.2f}', end='\r', flush=True)
