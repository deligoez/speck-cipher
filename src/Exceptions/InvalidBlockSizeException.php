<?php

declare(strict_types=1);

namespace Deligoez\Speck\Exceptions;

use Deligoez\Speck\Speck;
use Exception;

class InvalidBlockSizeException extends Exception
{
    /**
     * @throws \Deligoez\Speck\Exceptions\InvalidBlockSizeException
     */
    public static function build(): void
    {
        $message =
            'Invalid block size. ' .
            'Please use one of the following available block sizes: ' .
            implode(', ', array_keys(Speck::VALID_SETUPS));

        throw new InvalidBlockSizeException($message);
    }
}
