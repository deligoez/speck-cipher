<?php

declare(strict_types=1);

use Deligoez\Speck\Speck;

beforeEach(fn () => $this->numberOfTests = 1000);

test('Random speck vectors', function ($blockSize, $keySize): void {
    for ($i = 0; $i < $this->numberOfTests; $i++) {
        $key = gmp_random_bits($keySize);
        $plaintxt = gmp_random_bits($blockSize);

        $cipher = new Speck($key, $keySize, $blockSize);

        $ciphertxt = $cipher->encrypt($plaintxt);

        $this->assertEquals(
            expected: $ciphertxt,
            actual: $cipher->encrypt($plaintxt),
            message: "Encryption failed with the key: {$key} for the plain text: {$plaintxt}"
        );

        $this->assertEquals(
            expected: $plaintxt,
            actual: $cipher->decrypt($ciphertxt),
            message: "Decryption failed with the key: {$key} for the cipher text: {$ciphertxt}"
        );
    }
})->with([
    [32, 64],
    [48, 72],
    [48, 96],
    [64, 96],
    [64, 128],
    [96, 96],
    [96, 144],
    [128, 128],
    [128, 192],
    [128, 256],
]);
