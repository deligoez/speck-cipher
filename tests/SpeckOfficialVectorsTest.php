<?php

declare(strict_types=1);

use Deligoez\Speck\Speck;

test('32/64', function (): void {
    $key = gmp_init('0x1918111009080100');
    $plaintxt = gmp_init('0x6574694c');
    $ciphertxt = gmp_init('0xa86842f2');
    $block_size = 32;
    $key_size = 64;

    $cipher = new Speck($key, $key_size, $block_size);

    $this->assertEquals($ciphertxt, $cipher->encrypt($plaintxt));
    $this->assertEquals($plaintxt, $cipher->decrypt($ciphertxt));
});

test('48/72', function (): void {
    $key = gmp_init('0x1211100a0908020100');
    $plaintxt = gmp_init('0x20796c6c6172');
    $ciphertxt = gmp_init('0xc049a5385adc');
    $block_size = 48;
    $key_size = 72;

    $cipher = new Speck($key, $key_size, $block_size);

    $this->assertEquals($ciphertxt, $cipher->encrypt($plaintxt));
    $this->assertEquals($plaintxt, $cipher->decrypt($ciphertxt));
});

test('48/96', function (): void {
    $key = gmp_init('0x1a19181211100a0908020100');
    $plaintxt = gmp_init('0x6d2073696874');
    $ciphertxt = gmp_init('0x735e10b6445d');
    $block_size = 48;
    $key_size = 96;

    $cipher = new Speck($key, $key_size, $block_size);

    $this->assertEquals($ciphertxt, $cipher->encrypt($plaintxt));
    $this->assertEquals($plaintxt, $cipher->decrypt($ciphertxt));
});

test('64/96', function (): void {
    $key = gmp_init('0x131211100b0a090803020100');
    $plaintxt = gmp_init('0x74614620736e6165');
    $ciphertxt = gmp_init('0x9f7952ec4175946c');
    $block_size = 64;
    $key_size = 96;

    $cipher = new Speck($key, $key_size, $block_size);

    $this->assertEquals($ciphertxt, $cipher->encrypt($plaintxt));
    $this->assertEquals($plaintxt, $cipher->decrypt($ciphertxt));
});

test('64/128', function (): void {
    $key = gmp_init('0x1b1a1918131211100b0a090803020100');
    $plaintxt = gmp_init('0x3b7265747475432d');
    $ciphertxt = gmp_init('0x8c6fa548454e028b');
    $block_size = 64;
    $key_size = 128;

    $cipher = new Speck($key, $key_size, $block_size);

    $this->assertEquals($ciphertxt, $cipher->encrypt($plaintxt));
    $this->assertEquals($plaintxt, $cipher->decrypt($ciphertxt));
});

test('96/96', function (): void {
    $key = gmp_init('0x0d0c0b0a0908050403020100');
    $plaintxt = gmp_init('0x65776f68202c656761737520');
    $ciphertxt = gmp_init('0x9e4d09ab717862bdde8f79aa');
    $block_size = 96;
    $key_size = 96;

    $cipher = new Speck($key, $key_size, $block_size);

    $this->assertEquals($ciphertxt, $cipher->encrypt($plaintxt));
    $this->assertEquals($plaintxt, $cipher->decrypt($ciphertxt));
});

test('96/144', function (): void {
    $key = gmp_init('0x1514131211100d0c0b0a0908050403020100');
    $plaintxt = gmp_init('0x656d6974206e69202c726576');
    $ciphertxt = gmp_init('0x2bf31072228a7ae440252ee6');
    $block_size = 96;
    $key_size = 144;

    $cipher = new Speck($key, $key_size, $block_size);

    $this->assertEquals($ciphertxt, $cipher->encrypt($plaintxt));
    $this->assertEquals($plaintxt, $cipher->decrypt($ciphertxt));
});

test('128/128', function (): void {
    $key = gmp_init('0x0f0e0d0c0b0a09080706050403020100');
    $plaintxt = gmp_init('0x6c617669757165207469206564616d20');
    $ciphertxt = gmp_init('0xa65d9851797832657860fedf5c570d18');
    $block_size = 128;
    $key_size = 128;

    $cipher = new Speck($key, $key_size, $block_size);

    $this->assertEquals($ciphertxt, $cipher->encrypt($plaintxt));
    $this->assertEquals($plaintxt, $cipher->decrypt($ciphertxt));
});

test('128/192', function (): void {
    $key = gmp_init('0x17161514131211100f0e0d0c0b0a09080706050403020100');
    $plaintxt = gmp_init('0x726148206665696843206f7420746e65');
    $ciphertxt = gmp_init('0x1be4cf3a13135566f9bc185de03c1886');
    $block_size = 128;
    $key_size = 192;

    $cipher = new Speck($key, $key_size, $block_size);

    $this->assertEquals($ciphertxt, $cipher->encrypt($plaintxt));
    $this->assertEquals($plaintxt, $cipher->decrypt($ciphertxt));
});

test('128/256', function (): void {
    $key = gmp_init('0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100');
    $plaintxt = gmp_init('0x65736f6874206e49202e72656e6f6f70');
    $ciphertxt = gmp_init('0x4109010405c0f53e4eeeb48d9c188f43');
    $block_size = 128;
    $key_size = 256;

    $cipher = new Speck($key, $key_size, $block_size);

    $this->assertEquals($ciphertxt, $cipher->encrypt($plaintxt));
    $this->assertEquals($plaintxt, $cipher->decrypt($ciphertxt));
});
