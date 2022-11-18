<?php

declare(strict_types=1);

namespace Deligoez\Speck\Exceptions;

use Deligoez\Speck\Speck;
use Exception;

class InvalidKeySizeException extends Exception
{
    /**
     * @throws \Deligoez\Speck\Exceptions\InvalidKeySizeException
     */
    public static function build(int $blockSize): void
    {
        $message =
            'Invalid key size for selected block size. ' .
            'Please use one of the following available key sizes: ' .
            implode(', ', array_keys(Speck::VALID_SETUPS[$blockSize]));

        throw new InvalidKeySizeException($message);
    }
}
