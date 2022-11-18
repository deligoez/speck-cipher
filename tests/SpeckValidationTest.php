<?php

declare(strict_types=1);

use Deligoez\Speck\Exceptions\InvalidBlockSizeException;
use Deligoez\Speck\Exceptions\InvalidKeySizeException;
use Deligoez\Speck\Speck;

it('throws InvalidBlockSizeException for invalid block sizes', function () {
    new Speck(blockSize: 1);
})->expectException(InvalidBlockSizeException::class);

it('throws InvalidKeySizeException for invalid key sizes', function (): void {
    new Speck(blockSize: 128, keySize: 1);
})->expectException(InvalidKeySizeException::class);
