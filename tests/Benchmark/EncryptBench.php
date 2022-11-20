<?php

declare(strict_types=1);

namespace Deligoez\Speck\Tests\Benchmark;

use Deligoez\Speck\Speck;
use PhpBench\Benchmark\Metadata\Annotations\Iterations;
use PhpBench\Benchmark\Metadata\Annotations\Revs;

class EncryptBench
{
    /**
     * @Revs(10000)
     * @Iterations(5)
     */
    public function benchEncrypt(): void
    {
        $key = gmp_init('0x1918111009080100');
        $plaintxt = gmp_init('0x6574694c');
        $ciphertxt = gmp_init('0xa86842f2');
        $block_size = 32;
        $key_size = 64;

        $cipher = new Speck($key, $key_size, $block_size);

        $cipher->encrypt($plaintxt);
        $cipher->decrypt($ciphertxt);
    }
}
