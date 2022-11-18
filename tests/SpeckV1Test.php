<?php

declare(strict_types=1);

use Deligoez\Speck\SpeckV1;

test('Speck 32/64 offical vector', function (): void {
    $keys = [0x1918, 0x1110, 0x0908, 0x0100];
    $plainText = [0x6574, 0x694C];
    $cipherText = [0xA868, 0x42F2];

    $speck = new SpeckV1(bits: 64, rounds: 22);

    dd($speck->encryptRaw($plainText, $keys));

//    $this->assertEquals($speck->encrypt($plainText, $key), $cipherText);
//    $this->assertEquals($speck->decrypt($cipherText, $key), $plainText);
});

test('Speck 32/64', function (): void {
    $key = [0x1918, 0x1110, 0x0908, 0x0100];
    $plainText = 0x6574694C;
    $cipherText = 0xA86842F2;

    $speck = new SpeckV1(bits: 16, rounds: 22);

    $this->assertEquals($speck->encrypt($plainText, $key), $cipherText);
    $this->assertEquals($speck->decrypt($cipherText, $key), $plainText);
});

it('can test', function () {
    $speck = new SpeckV1(
        bits: 16,
        rounds: 22,
        rightRotations: 7,
        leftRotations: 2,
    );

    $key = [0x0100, 0x0908, 0x1110, 0x1918];
    $originalInteger = 0x694C6574;
    $obfuscatedInteger = $speck->encrypt($originalInteger, $key);

    $this->assertEquals($obfuscatedInteger, 0x42F2A868);
    $this->assertEquals($originalInteger, $speck->decrypt($obfuscatedInteger, $key));
});

test('try', function (): void {
    $settings = [
        ['bits' => 8,  'rounds' => 22, 'rightRotations' => 7, 'leftRotations' => 2],
        ['bits' => 10, 'rounds' => 22, 'rightRotations' => 7, 'leftRotations' => 2],
        ['bits' => 15, 'rounds' => 22, 'rightRotations' => 7, 'leftRotations' => 2],
        ['bits' => 16, 'rounds' => 22, 'rightRotations' => 7, 'leftRotations' => 2],
        ['bits' => 20, 'rounds' => 22, 'rightRotations' => 7, 'leftRotations' => 2],
        ['bits' => 24, 'rounds' => 22, 'rightRotations' => 8, 'leftRotations' => 3],
        ['bits' => 25, 'rounds' => 22, 'rightRotations' => 8, 'leftRotations' => 3],
        ['bits' => 26, 'rounds' => 22, 'rightRotations' => 8, 'leftRotations' => 3],
    ];

    foreach ($settings as $setting) {
        $keys = [];
        $maxKeyValue = 2 ** $setting['bits'];

        for ($i = 0; $i < 16; $i++) {
            $key = [];
            $keyLength = $i % 2 ? 4 : 2;

            for ($j = 0; $j < $keyLength; $j++) {
                $key[] = random_int(1, $maxKeyValue);
            }
            $keys[] = $key;
        }

        $testValues = [];
        $maxTestValue = 2 ** ($setting['bits'] * 2) - 1;
        for ($i = 0; $i < 256; $i++) {
            $testValues[] = random_int(1, $maxTestValue);
        }

        $speck = new SpeckV1($setting['bits'], $setting['rounds'], $setting['rightRotations'], $setting['leftRotations']);
        foreach ($testValues as $testValue) {
            foreach ($keys as $key) {
                $cipher = $speck->encrypt($testValue, $key);
                $plain = $speck->decrypt($cipher, $key);

                $this->assertEquals($cipher, $plain);
            }
        }
    }
});
