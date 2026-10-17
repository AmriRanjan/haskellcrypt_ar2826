module Crypt ( gcd, smallestCoPrimeOf, computeCoeffs, inverse
             , modPow, genKeys, rsaEncrypt, rsaDecrypt
             , alphaOrd, alphaChr, (<+>), (<->)
             , ecbEncrypt, ecbDecrypt, cbcEncrypt, cbcDecrypt ) where

import Data.Char

import Prelude hiding (gcd)

{-
The advantage of symmetric encryption schemes like AES is that they are efficient
and we can encrypt data of arbitrary size. The problem is how to share the key.
The flaw of the RSA is that it is slow and we can only encrypt data of size lower
than the RSA modulus n, usually around 1024 bits (64 bits for this exercise!).

We usually encrypt messages with a private encryption scheme like AES-256 with
a symmetric key k. The key k of fixed size 256 bits for example is then exchanged
via the aymmetric RSA.
-}

-------------------------------------------------------------------------------
-- PART 1 : asymmetric encryption

-- | Returns the greatest common divisor of its two arguments
gcd :: Int -> Int -> Int
gcd m 0 = m
gcd m n = gcd n (m `mod` n)

-- | Returns the smallest integer that is coprime with phi
smallestCoPrimeOf :: Int -> Int
smallestCoPrimeOf m = head [n | n <- [2..], gcd m n == 1]

-- | Calculates (n^k mod m)
modPow :: Int -> Int -> Int -> Int
modPow n k m
 | k == 0 = 1 `mod` m
 | r == 0 = modPow (n ^ 2 `mod` m) q m
 | otherwise = (n * modPow ((n ^ 2) `mod` m) q m) `mod` m
 where
    q = k `div` 2
    r = k `mod` 2

-- | Computes Bézout coefficients for two integers
computeCoeffs :: Int -> Int -> (Int, Int)
computeCoeffs a 0 = (1, 0)
computeCoeffs a b = (v, u - q * v)
 where
    (q, r) = quotRem a b
    (u, v) = computeCoeffs b r

-- | Inverse of n modulo m
inverse :: Int -> Int -> Int
inverse n m
 | gcd n m /= 1 = error "inverse: n and m aren ot coprime, gcd (n, m) must = 1!"
 | otherwise = u `mod` m
 where
    (u, _) = computeCoeffs n m

{-|
Generates keys pairs (public, private) = ((e, n), (d, n))
given two "large" distinct primes, p and q
-}
genKeys :: Int -> Int -> ((Int, Int), (Int, Int))
genKeys p q = ((e, n), (d, n))
 where
    n = p * q
    phi = (p - 1) * (q - 1)
    e = smallestCoPrimeOf phi
    d = inverse e phi

-- | This function performs RSA encryption
rsaEncrypt :: Int        -- ^ value to encrypt
           -> (Int, Int) -- ^ public key
           -> Int
rsaEncrypt x (e, n) = modPow x e n

-- | This function performs RSA decryption
rsaDecrypt :: Int        -- ^ value to decrypt
           -> (Int, Int) -- ^ private key
           -> Int
rsaDecrypt c (d, n) = modPow c d n

-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

-- | Returns position of a letter in the alphabet
alphaOrd :: Char -> Int
alphaOrd c = ord c - ord 'a'

-- | Returns the n^th letter
alphaChr :: Int -> Char
alphaChr n = chr (ord 'a' + n)

-- | "adds" two letters
(<+>) :: Char -> Char -> Char
c1 <+> c2 = alphaChr ((alphaOrd c1 + alphaOrd c2) `mod` 26)

-- | "subtracts" two letters
(<->) :: Char -> Char -> Char
c1 <-> c2 = alphaChr ((alphaOrd c1 - alphaOrd c2) `mod` 26)

-- the next functions present
-- 2 modes of operation for block ciphers : ECB and CBC
-- based on a symmetric encryption function e/d such as "add"

-- | ecb (electronic codebook) encryption with block size of a letter
ecbEncrypt :: Char -> [Char] -> [Char]
ecbEncrypt k m = [c <+> k | c <- m]

-- | ecb (electronic codebook) decryption with a block size of a letter
ecbDecrypt :: Char -> [Char] -> [Char]
ecbDecrypt k c = [x <-> k | x <- c]

-- | cbc (cipherblock chaining) encryption with block size of a letter
cbcEncrypt :: Char   -- ^ public key
           -> Char   -- ^ initialisation vector `iv`
           -> [Char] -- ^ message `m`
           -> [Char]
cbcEncrypt k iv [] = []
cbcEncrypt k iv m = c : cbcEncrypt k c (tail m)
 where
    c = (head m <+> iv) <+> k

-- | cbc (cipherblock chaining) decryption with block size of a letter
cbcDecrypt :: Char   -- ^ private key
           -> Char   -- ^ initialisation vector `iv`
           -> [Char] -- ^ message `m`
           -> [Char]
cbcDecrypt k iv [] = []
cbcDecrypt k iv c = x : cbcDecrypt k (head c) (tail c)
 where
    x = (head c <-> k) <-> iv