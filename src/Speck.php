<?php

declare(strict_types=1);

namespace Deligoez\Speck;

use Deligoez\Speck\Exceptions\InvalidBlockSizeException;
use Deligoez\Speck\Exceptions\InvalidKeySizeException;
use GMP;

class Speck
{
    // blockSize => [[keySize => numberOfRounds]]
    public const VALID_SETUPS = [
        32 => [64 => 22],
        48 => [72 => 22, 96 => 23],
        64 => [96 => 26, 128 => 27],
        96 => [96 => 28, 144 => 29],
        128 => [128 => 32, 192 => 33, 256 => 34],
    ];
    protected const VALID_MODES = ['ECB', 'CTR', 'CBC', 'PCBC', 'CFB', 'OFB'];

    protected int $wordSize;
    protected int $rounds;
    protected GMP $modMask;
    protected GMP $modMaskSub;

    /** Number of left rotations */
    protected int $betaShift;

    /** Number of right rotations */
    protected int $alphaShift;

    /** @var array<GMP> */
    protected array $keySchedule;

    /**
     * @throws \Deligoez\Speck\Exceptions\InvalidBlockSizeException
     * @throws \Deligoez\Speck\Exceptions\InvalidKeySizeException
     */
    public function __construct(
        protected int|GMP $key,
        protected int $keySize = 128,
        protected int $blockSize = 128,
    ) {
        // Block size validation
        if (! array_key_exists($this->blockSize, self::VALID_SETUPS)) {
            InvalidBlockSizeException::build();
        }

        // Key size validation
        if (! array_key_exists($this->keySize, self::VALID_SETUPS[$this->blockSize])) {
            InvalidKeySizeException::build($this->blockSize);
        }

        $this->wordSize = $this->blockSize >> 1;
        $this->rounds = self::VALID_SETUPS[$this->blockSize][$keySize];

        // Mod mask for modular subtraction
        $this->modMaskSub = gmp_pow(num: 2, exponent: $this->wordSize);

        // Create properly sized bit mask for truncating addition and left shift outputs
        $this->modMask = gmp_sub($this->modMaskSub, num2: 1);

        // Setup circular shift parameters
        $this->betaShift = $this->blockSize === 32 ? 2 : 3;
        $this->alphaShift = $this->blockSize === 32 ? 7 : 8;

        // Parse the given key and truncate it to the key length
        $this->key &= ((gmp_pow(2, $this->keySize)) - 1);

        // Pre-compile key schedule
        $this->keySchedule = [gmp_and($this->key, $this->modMask)];

        $lSchedule = [];
        $count = (int) ($this->keySize / $this->wordSize);
        for ($i = 1; $i < $count; $i++) {
            $lSchedule[] = gmp_and($this->gmp_shiftr($this->key, $i * $this->wordSize), $this->modMask);
        }

        for ($i = 0; $i < $this->rounds - 1; $i++) {
            [$lSchedule[], $this->keySchedule[]] = $this->round($lSchedule[$i], $this->keySchedule[$i], $i);
        }
    }

    // region Encryption

    /**
     * Complete one round of Feistel operation.
     *
     * @param $upperWord
     * @param $lowerWord
     * @param $k
     * @return int[]
     */
    protected function round($upperWord, $lowerWord, $k): array
    {
        $rs_x = (($upperWord << ($this->wordSize - $this->alphaShift)) + ($upperWord >> $this->alphaShift)) & $this->modMask;
        $add_sxy = ($rs_x + $lowerWord) & $this->modMask;
        $new_x = $k ^ $add_sxy;
        $ls_y = (($lowerWord >> ($this->wordSize - $this->betaShift)) + ($lowerWord << $this->betaShift)) & $this->modMask;
        $new_y = $new_x ^ $ls_y;

        return [$new_x, $new_y];
    }

    protected function encryptRaw(GMP $upperWord, GMP $lowerWord): array
    {
        foreach ($this->keySchedule as $k) {
            [$upperWord, $lowerWord] = $this->round($upperWord, $lowerWord, $k);
        }

        return [$upperWord, $lowerWord];
    }

    public function encrypt(int|GMP $plainText): GMP
    {
        $b = gmp_and($this->gmp_shiftr($plainText, $this->wordSize), $this->modMask);
        $a = gmp_and($plainText, $this->modMask);

        [$b, $a] = $this->encryptRaw($b, $a);

        return ($b << $this->wordSize) + $a;
    }

    // endregion

    // region Decryption

    /**
     * Complete one round of reverse Feistel operation.
     *
     * @param $upperWord
     * @param $lowerWord
     * @param $k
     * @return int[]
     */
    protected function reverseRound($upperWord, $lowerWord, $k): array
    {
        $xor_xy = $upperWord ^ $lowerWord;
        $lowerWord = (($xor_xy << ($this->wordSize - $this->betaShift)) + ($xor_xy >> $this->betaShift)) & $this->modMask;
        $xor_xk = $upperWord ^ $k;
        $msub = (($xor_xk - $lowerWord) + $this->modMaskSub) % $this->modMaskSub;
        $upperWord = (($msub >> ($this->wordSize - $this->alphaShift)) + ($msub << $this->alphaShift)) & $this->modMask;

        return [$upperWord, $lowerWord];
    }

    protected function decryptRaw(GMP $upperWord, GMP $lowerWord): array
    {
        foreach (array_reverse($this->keySchedule) as $k) {
            $this->reverseRound($upperWord, $lowerWord, $k);
        }

        return [$upperWord, $lowerWord];
    }

    public function decrypt(int|GMP $ciphertext): GMP|int
    {
        $b = ($ciphertext >> $this->wordSize) & $this->modMask;
        $a = $ciphertext & $this->modMask;

        [$b, $a] = $this->decryptRaw($b, $a);

        return ($b << $this->wordSize) + $a;
    }

    // endregion

    // region Helpers

    private function gmp_shiftl(int|GMP $x, int $n): GMP
    {
        return gmp_mul($x, gmp_pow(2, $n));
    }

    private function gmp_shiftr(int|GMP $x, int $n): GMP
    {
        return gmp_div($x, gmp_pow(2, $n));
    }

    // endregion
}
