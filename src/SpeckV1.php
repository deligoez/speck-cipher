<?php

namespace Deligoez\Speck;

class SpeckV1
{
    protected int $bitMax;
    protected int $bitMask;

    public function __construct(
        protected int $bits = 16,
        protected int $rounds = 22,
        protected int $rightRotations = 7,
        protected int $leftRotations = 2,
    ) {
        $this->bitMax = 2 ** $this->bits;
        $this->bitMask = $this->bitMax - 1;
    }

    public function rotateRight(int $x, int $numberOfRotations): int
    {
        return ($x >> $numberOfRotations) | (($x << ($this->bits - $numberOfRotations)) & $this->bitMask);
    }

    public function rotateLeft(int $x, int $numberOfRotations): int
    {
        return (($x << $numberOfRotations) & $this->bitMask) | ($x >> ($this->bits - $numberOfRotations));
    }

    /**
     * Complete one round of Feistel operation.
     *
     * @param  int|null  $x
     * @param  int  $y
     * @param  int  $k
     * @return int[]
     */
    public function round(?int $x, int $y, int $k): array
    {
        $x = $this->rotateRight(x: $x, numberOfRotations: $this->rightRotations);
        $x = ($x + $y) & $this->bitMask;
        $x ^= $k;
        $y = $this->rotateLeft(x: $y, numberOfRotations: $this->leftRotations);
        $y ^= $x;

        return [$x, $y];
    }

    /**
     * Complete one round of inverse Feistel operation.
     *
     * @param  int|null  $x
     * @param  int  $y
     * @param  int  $k
     * @return array
     */
    public function roundReverse(?int $x, int $y, int $k): array
    {
        $y ^= $x;
        $y = $this->rotateRight(x: $y, numberOfRotations: $this->leftRotations);
        $x ^= $k;
        $x = ($x - $y) & $this->bitMask;
        $x = $this->rotateLeft(x: $x, numberOfRotations: $this->rightRotations);

        return [$x, $y];
    }

    public function encryptRaw(array $plainTexts, array $keys): array
    {
        [$y, $x] = $plainTexts;
        $b = $keys[0];
        $a = array_slice($keys, offset: 1);

        [$x, $y] = $this->round(x: $x, y: $y, k: $b);

        $count = count($a);
        for ($i = 0; $i < $this->rounds - 1; $i++) {
            $j = $i % $count;
            [$a[$j], $b] = $this->round(x: $a[$j] ?? null, y: $b, k: $i);
            [$x, $y] = $this->round(x: $x, y: $y, k: $b);
        }

        return [$y, $x];
    }

    public function decryptRaw(array $cipherTexts, array $keys): array
    {
        [$y, $x] = $cipherTexts;
        $b = $keys[0];
        $a = array_slice($keys, offset: 1);

        for ($i = 0; $i < $this->rounds - 1; $i++) {
            $j = $i % count($a);
            [$a[$j], $b] = $this->round(x: $a[$j], y: $b, k: $i);
        }

        for ($i = 0; $i < $this->rounds; $i++) {
            $j = ($this->rounds - 2 - $i) % count($a);
            [$x, $y] = $this->roundReverse(x: $x, y: $y, k: $b);
            [$a[$j], $b] = $this->roundReverse(x: $a[$j] ?? null, y: $b, k: $this->rounds - 2 - $i);
        }

        return [$y, $x];
    }

    public function encrypt(int $input, array $keys): int
    {
        $result = $this->encryptRaw(
            plainTexts: [
                (int) ($input / $this->bitMax) | 0,
                $input & $this->bitMask,
            ],
            keys: $keys
        );

        return $result[0] * $this->bitMax + $result[1];
    }

    public function decrypt(int $input, array $keys): int
    {
        $result = $this->decryptRaw(
            cipherTexts: [
                (int) ($input / $this->bitMax) | 0,
                $input & $this->bitMask,
            ],
            keys: $keys
        );

        return $result[0] * $this->bitMax + $result[1];
    }
}
