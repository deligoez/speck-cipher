<?php

declare(strict_types=1);

namespace Deligoez\Speck;

use Deligoez\Speck\Exceptions\InvalidBlockSizeException;
use Deligoez\Speck\Exceptions\InvalidKeySizeException;
use GMP;

/**
 * Speck Block Cipher Object.
 */
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

    /** Integer representation of the encryption key */
    protected int|GMP $key;

    /** Integer representing the size of the encryption key in bits */
    protected int $keySize;

    /** Integer representing the size of the blocks in bits */
    protected int $blockSize;

    /** Integer representing the size of the words in bits */
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
     * Initialize an instance of the Speck Block Cipher.
     *
     * @throws \Deligoez\Speck\Exceptions\InvalidBlockSizeException
     * @throws \Deligoez\Speck\Exceptions\InvalidKeySizeException
     */
    public function __construct(
        int|GMP $key,
        int $keySize = 128,
        int $blockSize = 128,
    ) {
        // Block size validation
        if (! array_key_exists($blockSize, self::VALID_SETUPS)) {
            InvalidBlockSizeException::build();
        }

        // Key size validation
        if (! array_key_exists($keySize, self::VALID_SETUPS[$blockSize])) {
            InvalidKeySizeException::build($blockSize);
        }

        $this->keySize = $keySize;
        $this->blockSize = $blockSize;

        $this->wordSize = $this->blockSize >> 1;
        $this->rounds = self::VALID_SETUPS[$this->blockSize][$keySize];

        // Mod mask for modular subtraction
        $this->modMaskSub = gmp_pow(num: 2, exponent: $this->wordSize);

        // Create properly sized bit mask for truncating addition and left shift outputs
        $this->modMask = gmp_sub(num1: $this->modMaskSub, num2: 1);

        // Setup circular shift parameters
        $this->betaShift = $this->blockSize === 32 ? 2 : 3;
        $this->alphaShift = $this->blockSize === 32 ? 7 : 8;

        // Parse the given key and truncate it to the key length
        $this->key = gmp_and($key, ((gmp_pow(2, $this->keySize)) - 1));

        // Pre-compile key schedule
        $this->keySchedule = [gmp_and($this->key, $this->modMask)];

        $lSchedule = [];
        $count = (int) ($this->keySize / $this->wordSize);
        for ($i = 1; $i < $count; $i++) {
            $lSchedule[] = gmp_and($this->gmp_shiftr($this->key, $i * $this->wordSize), $this->modMask);
        }

        for ($i = 0; $i < $this->rounds - 1; $i++) {
            [$lSchedule[], $this->keySchedule[]] = $this->round($lSchedule[$i], $this->keySchedule[$i], gmp_init($i));
        }
    }

    // region Encryption

    /**
     * Complete one round of Feistel operation.
     *
     * @param \GMP $upperWord Upper bits of the current plain text.
     * @param \GMP $lowerWord Lower bits of the current plain text.
     * @param \GMP $key       Round key.
     *
     * @return array{0: GMP, 1: GMP } Upper and lower cipher text segments.
     */
    protected function round(GMP $upperWord, GMP $lowerWord, GMP $key): array
    {
        $upperWord = gmp_and(gmp_add($this->gmp_shiftl($upperWord, ($this->wordSize - $this->alphaShift)), $this->gmp_shiftr($upperWord, $this->alphaShift)), $this->modMask);
        $upperWord = gmp_and(gmp_add($upperWord, $lowerWord), $this->modMask);
        $upperWord = gmp_xor($key, $upperWord);

        $lowerWord = gmp_and(gmp_add($this->gmp_shiftr($lowerWord, ($this->wordSize - $this->betaShift)), ($this->gmp_shiftl($lowerWord, $this->betaShift))), $this->modMask);
        $lowerWord = gmp_xor($upperWord, $lowerWord);

        return [$upperWord, $lowerWord];
    }

    /**
     * Completes appropriate number of Speck Feistel functions to encrypt provided words.
     * Round number is based off of number of elements in the key schedule.
     *
     * @param \GMP $upperWord Upper bits of the current plain text input. Limited by the word size of currenly configured cipher.
     * @param \GMP $lowerWord Lower bits of the current plain text input. Limited by the word size of currenly configured cipher.
     *
     * @return array{ 0: GMP, 1: GMP } Upper and lower bits of the cipher text words.
     */
    protected function encryptRaw(GMP $upperWord, GMP $lowerWord): array
    {
        foreach ($this->keySchedule as $key) {
            [$upperWord, $lowerWord] = $this->round($upperWord, $lowerWord, $key);
        }

        return [$upperWord, $lowerWord];
    }

    /**
     * Process a new plain text into the cipher text based on current cipher setup.
     *
     * @param \GMP|string|int $plainText Integer value to encrypt.
     *
     * @return \GMP Encrypted integer value
     */
    public function encrypt(GMP|string|int $plainText): GMP
    {
        $b = gmp_and($this->gmp_shiftr($plainText, $this->wordSize), $this->modMask);
        $a = gmp_and($plainText, $this->modMask);

        [$b, $a] = $this->encryptRaw($b, $a);

        return gmp_add($this->gmp_shiftl($b, $this->wordSize), $a);
    }

    // endregion

    // region Decryption

    /**
     * Complete one round of reverse Feistel operation.
     *
     * @param \GMP $upperWord Upper bits of the current cipher text.
     * @param \GMP $lowerWord Lower bits of the current cipher text.
     * @param \GMP $key       Round key.
     *
     * @return array{0: GMP, 1: GMP } Upper and lower plain text segments.
     */
    protected function reverseRound(GMP $upperWord, GMP $lowerWord, GMP $key): array
    {
        $upperWord = gmp_xor($upperWord, $lowerWord);
        $upperWord = gmp_and(gmp_add($this->gmp_shiftl($upperWord, ($this->wordSize - $this->betaShift)), ($this->gmp_shiftr($upperWord, $this->betaShift))), $this->modMask);
        $upperWord = gmp_xor($upperWord, $key);

        $lowerWord = gmp_mod(gmp_add(gmp_sub($upperWord, $lowerWord), $this->modMaskSub), $this->modMaskSub);
        $lowerWord = gmp_and(gmp_add($this->gmp_shiftr($lowerWord, ($this->wordSize - $this->alphaShift)), ($this->gmp_shiftl($lowerWord, $this->alphaShift))), $this->modMask);

        return [$upperWord, $lowerWord];
    }

    /**
     * Completes appropriate number of Speck Feistel functions to decrypt provided words.
     * Round number is based off of number of elements in the key schedule.
     *
     * @param \GMP $upperWord Upper bits of the current cipher text input. Limited by the word size of currenly configured cipher.
     * @param \GMP $lowerWord Lower bits of the current cipher text input. Limited by the word size of currenly configured cipher.
     *
     * @return array{ 0: GMP, 1: GMP } Upper and lower bits of the plain text words.
     */
    protected function decryptRaw(GMP $upperWord, GMP $lowerWord): array
    {
        foreach (array_reverse($this->keySchedule) as $key) {
            $this->reverseRound($upperWord, $lowerWord, $key);
        }

        return [$upperWord, $lowerWord];
    }

    /**
     * Process a cipher text into the plain text based on current cipher setup.
     *
     * @param \GMP|string|int $ciphertext Integer value to decrypt.
     *
     * @return \GMP Decrypted integer value
     */
    public function decrypt(GMP|string|int $ciphertext): GMP
    {
        $b = gmp_and($this->gmp_shiftr($ciphertext, $this->wordSize), $this->modMask);
        $a = gmp_and($ciphertext, $this->modMask);

        [$b, $a] = $this->decryptRaw($b, $a);

        return gmp_add($this->gmp_shiftl($b, $this->wordSize), $a);
    }

    // endregion

    // region Helpers

    /**
     * Bitwise left shift.
     * Moves all bits in the number to the left by the given number of places.
     *
     * @param \GMP|string|int $number         Number to bitwise left shift.
     * @param int             $numberOfShifts Number of places to shift.
     */
    protected function gmp_shiftl(GMP|string|int $number, int $numberOfShifts): GMP
    {
        return gmp_mul($number, gmp_pow(2, $numberOfShifts));
    }

    /**
     * Bitwise right shift.
     * Moves all bits in the number to the right by the given number of places.
     *
     * @param \GMP|string|int $number         Number to bitwise right shift.
     * @param int             $numberOfShifts Number of places to shift.
     */
    protected function gmp_shiftr(GMP|string|int $number, int $numberOfShifts): GMP
    {
        return gmp_div($number, gmp_pow(2, $numberOfShifts));
    }

    // endregion
}
