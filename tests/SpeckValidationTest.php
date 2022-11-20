<?php

declare(strict_types=1);

use Deligoez\Speck\Exceptions\InvalidBlockSizeException;
use Deligoez\Speck\Exceptions\InvalidKeySizeException;
use Deligoez\Speck\Speck;

it('throws InvalidBlockSizeException for invalid block sizes', function (): void {
    new Speck(key: 0x1918111009080100, blockSize: 1);
})->expectException(InvalidBlockSizeException::class);

it('throws InvalidKeySizeException for invalid key sizes', function (): void {
    new Speck(key: 0x1918111009080100, keySize: 1, blockSize: 128);
})->expectException(InvalidKeySizeException::class);
