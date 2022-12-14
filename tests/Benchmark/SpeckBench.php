<?php

declare(strict_types=1);

namespace Deligoez\Speck\Tests\Benchmark;

use Deligoez\Speck\Speck;
use GMP;
use PhpBench\Benchmark\Metadata\Annotations\BeforeMethods;
use PhpBench\Benchmark\Metadata\Annotations\Iterations;
use PhpBench\Benchmark\Metadata\Annotations\Revs;
use PhpBench\Benchmark\Metadata\Annotations\Warmup;

class SpeckBench
{
    protected Speck $cipher;
    protected GMP $plaintxt;
    protected GMP $ciphertxt;

    public function setup(): void
    {
        $this->plaintxt = gmp_init('0x6574694c');
        $this->ciphertxt = gmp_init('0xa86842f2');

        $key = gmp_init('0x1918111009080100');
        $block_size = 32;
        $key_size = 64;

        $this->cipher = new Speck($key, $key_size, $block_size);
    }

    /**
     * @Revs(10000)
     * @Iterations(5)
     * @Warmup(3)
     */
    public function benchCreateCipher(): void
    {
        $key = gmp_init('0x1918111009080100');
        $block_size = 32;
        $key_size = 64;

        new Speck($key, $key_size, $block_size);
    }

    /**
     * @Revs(10000)
     * @Iterations(5)
     * @Warmup(3)
     * @BeforeMethods({"setup"})
     */
    public function benchEncrypt(): void
    {
        $this->cipher->encrypt($this->plaintxt);
    }

    /**
     * @Revs(10000)
     * @Iterations(5)
     * @Warmup(3)
     * @BeforeMethods({"setup"})
     */
    public function benchDecrypt(): void
    {
        $this->cipher->decrypt($this->ciphertxt);
    }
}
