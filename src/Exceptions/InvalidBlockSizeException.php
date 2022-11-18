<?php

namespace Deligoez\Speck\Exceptions;

use Deligoez\Speck\Speck2;
use Exception;

class InvalidBlockSizeException extends Exception
{
    /**
     * @throws \Deligoez\Speck\Exceptions\InvalidBlockSizeException
     */
    public static function build(): void
    {
        $message =
            'Invalid block size. '.
            'Please use one of the following available block sizes: '.
            implode(', ', array_keys(Speck2::VALID_SETUPS));

        throw new InvalidBlockSizeException($message);
    }
}
