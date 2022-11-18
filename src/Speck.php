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
    protected int $betaShift;
    protected int $alphaShift;
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
        $this->modMaskSub = gmp_pow(2, $this->wordSize);

        // Create properly sized bit mask for truncating addition and left shift outputs
        $this->modMask = gmp_sub($this->modMaskSub, 1);

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
            $new_l_k = $this->encrypt_round($lSchedule[$i], $this->keySchedule[$i], $i);
            $lSchedule[] = $new_l_k[0];
            $this->keySchedule[] = $new_l_k[1];
        }
    }

    // region Encryption

    // Complete One Round of Feistel Operation
    protected function encrypt_round($x, $y, $k): array
    {
        $rs_x = (($x << ($this->wordSize - $this->alphaShift)) + ($x >> $this->alphaShift)) & $this->modMask;
        $add_sxy = ($rs_x + $y) & $this->modMask;
        $new_x = $k ^ $add_sxy;
        $ls_y = (($y >> ($this->wordSize - $this->betaShift)) + ($y << $this->betaShift)) & $this->modMask;
        $new_y = $new_x ^ $ls_y;

        return [$new_x, $new_y];
    }

    protected function encrypt_function(GMP $upperWord, GMP $lowerWord): array
    {
        $x = $upperWord;
        $y = $lowerWord;

        // Run encryption steps for appropriate number of rounds
        foreach ($this->keySchedule as $k) {
            $rs_x = (($x << ($this->wordSize - $this->alphaShift)) + ($x >> $this->alphaShift)) & $this->modMask;
            $add_sxy = ($rs_x + $y) & $this->modMask;
            $x = $k ^ $add_sxy;
            $ls_y = (($y >> ($this->wordSize - $this->betaShift)) + ($y << $this->betaShift)) & $this->modMask;
            $y = $x ^ $ls_y;
        }

        return [$x, $y];
    }

    public function encrypt(int|GMP $plainText): GMP
    {
        $b = gmp_and($this->gmp_shiftr($plainText, $this->wordSize), $this->modMask);
        $a = gmp_and($plainText, $this->modMask);

        [$b, $a] = $this->encrypt_function($b, $a);

        $ciphertext = ($b << $this->wordSize) + $a;

        return $ciphertext;
    }

    // endregion

    // region Decryption

    protected function decrypt_function(GMP $upperWord, GMP $lowerWord): array
    {
        $x = $upperWord;
        $y = $lowerWord;

        foreach (array_reverse($this->keySchedule) as $k) {
            $xor_xy = $x ^ $y;
            $y = (($xor_xy << ($this->wordSize - $this->betaShift)) + ($xor_xy >> $this->betaShift)) & $this->modMask;
            $xor_xk = $x ^ $k;
            $msub = (($xor_xk - $y) + $this->modMaskSub) % $this->modMaskSub;
            $x = (($msub >> ($this->wordSize - $this->alphaShift)) + ($msub << $this->alphaShift)) & $this->modMask;
        }

        return [$x, $y];
    }

    public function decrypt(int|GMP $ciphertext): GMP|int
    {
        $b = ($ciphertext >> $this->wordSize) & $this->modMask;
        $a = $ciphertext & $this->modMask;

        [$b, $a] = $this->decrypt_function($b, $a);

        $plaintext = ($b << $this->wordSize) + $a;

        return $plaintext;
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
