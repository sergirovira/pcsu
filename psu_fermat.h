#include <iostream>
#include <set>
#include <cassert>
#include <random>
#include "openfhe.h"

#include <chrono>

using namespace lbcrypto;

// Set to encode is in parties[i]
// Same idea as the code in SEAL with the exception of that this one returns a vector of 24 ciphertexts
std::vector<Ciphertext<DCRTPoly>> encrypt_set_a(std::vector<std::set<int64_t> > &parties, size_t i, size_t SET_SIZE, CryptoContext<DCRTPoly> &cryptoContext, KeyPair<DCRTPoly> &keyPair) {
	std::vector<std::vector<int64_t>> values(24, std::vector<int64_t>(SET_SIZE * SET_SIZE, 0));

	for (size_t r = 0; r < SET_SIZE; ++r) {
		size_t idx = 0; 
		for (auto id : parties[i]) {
			for (size_t b = 0; b < 24; ++b) {
				values[b][r * SET_SIZE + (idx + r) % SET_SIZE] = id % 2;
				id /= 2;
			}
			++idx;
		}
	}

	for (size_t b = 0; b < 24; ++b) {
		std::cout << "Value " << values[b] << ": ";
        std::cout << std::endl;
	}


	std::vector<Ciphertext<DCRTPoly>> res(24);
	for (size_t b = 0; b < 24; ++b) {
		Plaintext ptxt = cryptoContext->MakePackedPlaintext(values[b]);
		res[b] = cryptoContext->Encrypt(keyPair.publicKey, ptxt);
	}
	return res;
}

// Set to encode is in parties[i]
// Same idea as the code in SEAL with the exception of that this one returns a vector of 24 ciphertexts
std::vector<Ciphertext<DCRTPoly>> encrypt_set_b(std::vector<std::set<int64_t> > &parties, size_t i, size_t SET_SIZE, CryptoContext<DCRTPoly> &cryptoContext, KeyPair<DCRTPoly> &keyPair) {
	std::vector<std::vector<int64_t>> values(24, std::vector<int64_t>(SET_SIZE * SET_SIZE, 0));

	for (size_t r = 0; r < SET_SIZE; ++r) {
		size_t idx = 0; 
		for (auto id : parties[i]) {
			for (size_t b = 0; b < 24; ++b) {
				values[b][r * SET_SIZE + idx] = id % 2;
				id /= 2;
			}
			++idx;
		}
	}

	std::cout << "Value (in set B)" << ": ";
        std::cout << std::endl;
	for (size_t b = 0; b < 24; ++b) {
		std::cout << "Value " << values[b] << ": ";
        std::cout << std::endl;
	}

	std::vector<Ciphertext<DCRTPoly>> res(24);
	for (size_t b = 0; b < 24; ++b) {
		Plaintext ptxt = cryptoContext->MakePackedPlaintext(values[b]);
		res[b] = cryptoContext->Encrypt(keyPair.publicKey, ptxt);
	}
	return res;
}

// @brief This computes homomorphic comparison of two ciphertexts, a and b, encrypted under the same public key, 
//as 1 - \prod_{i=0}^{mu - 1} (1 - a_i - b_i - 2 * a_i * b_i), where a=(a_0,...,a_{mu - 1}) and b=(b_0,...,b_{mu - 1})
// @param a first ciphertext to compare
// @param b second ciphertext to compare
// @param SET_SIZE size of the set
// @param cryptoContext crypto context of the used scheme
// @return returns Enc(0) if A = B or Enc(1) if A != B
Ciphertext<DCRTPoly> equal_1(Ciphertext<DCRTPoly> a, Ciphertext<DCRTPoly> b, size_t SET_SIZE, CryptoContext<DCRTPoly> &cryptoContext) {
	Ciphertext<DCRTPoly> ctxt_res = a;
	//compte a XOR b as (a - b)^2
	ctxt_res = cryptoContext->EvalSub(a, b); // a - b
	ctxt_res = cryptoContext->EvalMult(ctxt_res, ctxt_res); // (a - b)^2
	std::vector<int64_t> v(SET_SIZE * SET_SIZE, 1);
	Plaintext ptxt;
	ptxt = cryptoContext->MakePackedPlaintext(v);
	ctxt_res = cryptoContext->EvalSub(ptxt, ctxt_res); // 1 - (a - b)^2 
	return ctxt_res;
}

/// @brief This computes B \ A assuming |A|=|B|=2^k for some integer k, where the elements of A and B are 24-bit identifiers.
/// It requires very specifically encrypted inputs (see further documentation).
/// @param A must be all possible permutations of A, i.e. |A| permuted repetitions.
/// @param B must be |B| repetitions of B, all in the *same* order
/// @return A ciphertext containing 0 in slot i  iff the i-th element in B is also in A
Ciphertext<DCRTPoly> PSU_2(std::vector<Ciphertext<DCRTPoly>> A, std::vector<Ciphertext<DCRTPoly>> &B, 
	size_t SET_SIZE, CryptoContext<DCRTPoly> &cryptoContext, KeyPair<DCRTPoly> &keyPair) {
	//Now we compute B \ A over the encrypted sets
	std::vector<int64_t> v(SET_SIZE * SET_SIZE, 1);
	Plaintext ptxt;
	ptxt = cryptoContext->MakePackedPlaintext(v);
	auto ctxt_ones = cryptoContext->Encrypt(keyPair.publicKey, ptxt);
	for (size_t b = 0; b < 24; ++b) {
	// Compute a XOR b as (a-b)^2
		A[b] = equal_1(A[b], B[b], SET_SIZE, cryptoContext);
	}
	
	auto output1 = cryptoContext->EvalMultMany(A);
	
	// collapse everything
	auto output = cryptoContext->EvalSub(ctxt_ones, output1);

	// get the first SET_SIZE slots to be Enc(0) iff the ith element is in boths sets, Enc(1) otherwise
	auto rot = output;
	for (size_t i = SET_SIZE / 2; i > 0; i /= 2) {
		rot = cryptoContext->EvalRotate(rot, SET_SIZE);
		output = cryptoContext->EvalMult(output, rot);
	}
	return output;
}

// IMPORTANT: this function does not work as expected, it needs to be revised and corrected!
// @brief This multiplies the encrypted and the output of PSU
// @param A encrypted set
// @param list output of PSU
// @param SET_SIZE size of the set
// @param cryptoContext crypto context of the used scheme
// @param keyPair was added for testing, remove it once it works properly
void mult_set(std::vector<Ciphertext<DCRTPoly>> &A,
	Ciphertext<DCRTPoly> &list, size_t SET_SIZE, CryptoContext<DCRTPoly> &cryptoContext, KeyPair<DCRTPoly> &keyPair) {
	std::vector<int64_t> mask(SET_SIZE, 0);
	for (size_t b = 0; b < SET_SIZE; ++b) {
		// Generate a mask with 1 in ith slot
		mask[b] = 1;
		Plaintext ptxt = cryptoContext->MakePackedPlaintext(mask);
		mask[b] = 0;
		auto t = cryptoContext->EvalInnerProduct(list, ptxt, 1);
		// now t should be Enc((0,...,0,list[b],0,...,0)) (list[b] is in bth position)
		// Something goes wrong here

		// Here we have the problem, we should be multiplying A[b] * list[b] and not A[b] * t
		A[b] = cryptoContext->EvalMult(A[b], t);
	}
}

// @brief This decrypts a set encrypted under encrypt_set_a or encrypted_set_b
std::set<uint32_t> decrypt_set(std::vector<Ciphertext<DCRTPoly>> &A, size_t SET_SIZE, KeyPair<DCRTPoly> &keyPair, CryptoContext<DCRTPoly> &cryptoContext) {
	std::vector<std::vector<long int>> bits(24, std::vector<long int>());
	std::set<uint32_t> result;
	long int num = 0;
	for (size_t i = 0; i < SET_SIZE; ++i) {
		for (uint j = 0; j < 24; ++j) {
			Plaintext ptxt;
			cryptoContext->Decrypt(keyPair.secretKey, A[j], &ptxt);
			bits[j] = ptxt->GetPackedValue();
			num += (long)bits[j][i]*pow(2, j);
		}
		result.insert(num);
		num = 0;
	}
	return result;
}

// @brief This was designed for testing, it is an alternative way of encrypting a set that allows to run mult_set on it. The difference is that this one
// returns a vector with SET_SIZE ciphertexts, each corresponding to the encryption (in a SIMD manner) each element of the set
std::vector<Ciphertext<DCRTPoly>> encrypt_to_mult(std::vector<std::set<int64_t> > &parties, size_t i, size_t SET_SIZE, CryptoContext<DCRTPoly> &cryptoContext, KeyPair<DCRTPoly> &keyPair) {
	std::vector<std::vector<int64_t>> values(SET_SIZE, std::vector<int64_t>(24, 0));

	size_t idx = 0;
	for (auto id : parties[i]) {
		for (size_t b = 0; b < 24; ++b) {
			values[idx][b] = id % 2;
			id /= 2;
		}
		++idx;
	}

	std::vector<Ciphertext<DCRTPoly>> res(SET_SIZE);
	for (size_t b = 0; b < SET_SIZE; ++b) {
		Plaintext ptxt = cryptoContext->MakePackedPlaintext(values[b]);
		res[b] = cryptoContext->Encrypt(keyPair.publicKey, ptxt);
	}
	return res;
}

// @brief This decrypts the A set encrypted via the prior function
std::set<uint32_t> decrypt_set_2(std::vector<Ciphertext<DCRTPoly>> &A, size_t SET_SIZE, KeyPair<DCRTPoly> &keyPair, CryptoContext<DCRTPoly> &cryptoContext) {
	std::vector<std::vector<long int>> bits(SET_SIZE, std::vector<long int>());
	std::set<uint32_t> result;
	long int num = 0;
	for (size_t i = 0; i < SET_SIZE; ++i) {
		Plaintext ptxt;
		cryptoContext->Decrypt(keyPair.secretKey, A[i], &ptxt);
		bits[i] = ptxt->GetPackedValue();
		for (size_t j = 0; j < 24; ++j) {
			num += (long)bits[i][j]*pow(2, j);
		}
		result.insert(num);
		num = 0;
	}
	return result;
}